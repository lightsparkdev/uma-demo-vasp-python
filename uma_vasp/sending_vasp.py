import time
from datetime import datetime
from typing import List, NoReturn

import requests
from flask import Flask, abort
from flask import request as flask_request
from lightspark import CurrencyUnit
from lightspark import LightsparkSyncClient as LightsparkClient
from lightspark import OutgoingPayment, PaymentDirection, TransactionStatus
from uma import (
    InvalidSignatureException,
    IPublicKeyCache,
    LnurlpResponse,
    PayReqResponse,
    UtxoWithAmount,
    compliance_from_payee_data,
    create_compliance_payer_data,
    create_counterparty_data_options,
    create_lnurlp_request_url,
    create_pay_request,
    fetch_public_key_for_vasp,
    parse_lnurlp_response,
    parse_pay_req_response,
    select_highest_supported_version,
    verify_uma_lnurlp_response_signature,
)

from uma_vasp.address_helpers import get_domain_from_uma_address
from uma_vasp.compliance_service import IComplianceService
from uma_vasp.config import Config
from uma_vasp.currencies import CURRENCIES
from uma_vasp.lightspark_helpers import get_node
from uma_vasp.sending_vasp_request_cache import ISendingVaspRequestCache
from uma_vasp.user import User
from uma_vasp.user_service import IUserService


class SendingVasp:
    def __init__(
        self,
        user_service: IUserService,
        compliance_service: IComplianceService,
        lightspark_client: LightsparkClient,
        pubkey_cache: IPublicKeyCache,
        request_cache: ISendingVaspRequestCache,
        config: Config,
    ) -> None:
        self.user_service = user_service
        self.compliance_service = compliance_service
        self.vasp_pubkey_cache = pubkey_cache
        self.lightspark_client = lightspark_client
        self.request_cache = request_cache
        self.config = config

    def handle_uma_lookup(self, receiver_uma: str):
        user = self._get_calling_user_or_abort()

        if not self.compliance_service.should_accept_transaction_to_vasp(
            receiving_vasp_domain=get_domain_from_uma_address(receiver_uma),
            sending_uma_address=user.get_uma_address(self.config),
            receiving_uma_address=receiver_uma,
        ):
            _abort_with_error(
                403, "Transactions to that receiving VASP are not allowed."
            )

        url = create_lnurlp_request_url(
            signing_private_key=self.config.get_signing_privkey(),
            receiver_address=receiver_uma,
            sender_vasp_domain=self.config.get_uma_domain(),
            is_subject_to_travel_rule=True,
        )

        response = requests.get(url, timeout=20)

        if response.status_code == 412:
            response = self._retry_lnurlp_with_version_negotiation(
                receiver_uma, response
            )

        if response.status_code != 200:
            _abort_with_error(
                424, f"Error fetching LNURLP: {response.status_code} {response.text}"
            )

        lnurlp_response: LnurlpResponse
        try:
            lnurlp_response = parse_lnurlp_response(response.text)
        except Exception as e:
            _abort_with_error(424, f"Error parsing LNURLP response: {e}")

        receiver_vasp_pubkey = fetch_public_key_for_vasp(
            vasp_domain=get_domain_from_uma_address(receiver_uma),
            cache=self.vasp_pubkey_cache,
        )

        try:
            verify_uma_lnurlp_response_signature(
                lnurlp_response, receiver_vasp_pubkey.signing_pubkey
            )
        except InvalidSignatureException as e:
            _abort_with_error(424, f"Error verifying LNURLP response signature: {e}")

        callback_uuid = self.request_cache.save_lnurlp_response_data(
            lnurlp_response=lnurlp_response,
            receiver_uma=receiver_uma,
            receiving_vasp_domain=self.config.get_uma_domain(),
        )
        sender_currencies = [
            CURRENCIES[currency]
            for currency in user.currencies
            if currency in CURRENCIES
        ]

        return {
            "senderCurrencies": [currency.to_dict() for currency in sender_currencies],
            "receiverCurrencies": [
                currency.to_dict() for currency in lnurlp_response.currencies
            ],
            "minSendableSats": lnurlp_response.min_sendable,
            "maxSendableSats": lnurlp_response.max_sendable,
            "callbackUuid": callback_uuid,
            # You might not actually send this to a client in practice.
            "receiverKycStatus": lnurlp_response.compliance.kyc_status.value,
        }

    def _retry_lnurlp_with_version_negotiation(
        self, receiver_uma: str, response: requests.Response
    ):
        response_body = response.json()
        supported_major_versions = response_body["supportedMajorVersions"]
        if not supported_major_versions or len(supported_major_versions) == 0:
            _abort_with_error(424, "No major versions supported by receiving VASP.")
        new_version = select_highest_supported_version(supported_major_versions)
        if not new_version:
            _abort_with_error(
                424, "No matching UMA version compatible with receiving VASP."
            )
        retry_url = create_lnurlp_request_url(
            signing_private_key=self.config.get_signing_privkey(),
            receiver_address=receiver_uma,
            sender_vasp_domain=self.config.get_uma_domain(),
            is_subject_to_travel_rule=True,
            uma_version_override=new_version,
        )
        return requests.get(retry_url, timeout=20)

    def handle_uma_payreq(self, callback_uuid: str):
        user = self._get_calling_user_or_abort()

        initial_request_data = self.request_cache.get_lnurlp_response_data(
            callback_uuid
        )
        if initial_request_data is None:
            _abort_with_error(404, f"Cannot find callback UUID {callback_uuid}")

        receiving_currency_code = flask_request.args.get("currencyCode")
        if receiving_currency_code is None:
            _abort_with_error(400, "Currency code is required.")

        receiving_currencies = initial_request_data.lnurlp_response.currencies
        receiving_currency = next(
            (
                currency
                for currency in receiving_currencies
                if currency.code == receiving_currency_code
            ),
            None,
        )
        if not receiving_currency:
            _abort_with_error(400, "Currency code is not supported.")

        amount = self._parse_and_validate_amount(
            flask_request.args.get("amount", ""),
            receiving_currency_code,
            initial_request_data.lnurlp_response,
        )

        receiver_vasp_pubkey = fetch_public_key_for_vasp(
            vasp_domain=initial_request_data.receiving_vasp_domain,
            cache=self.vasp_pubkey_cache,
        )

        node = get_node(self.lightspark_client, self.config.node_id)

        payer_compliance = create_compliance_payer_data(
            receiver_encryption_pubkey=receiver_vasp_pubkey.encryption_pubkey,
            signing_private_key=self.config.get_signing_privkey(),
            payer_identifier=user.get_uma_address(self.config),
            payer_kyc_status=user.kyc_status,
            travel_rule_info=self.compliance_service.get_travel_rule_info_for_transaction(
                sending_user_id=user.id,
                sending_uma_address=user.get_uma_address(self.config),
                receiving_uma_address=initial_request_data.receiver_uma,
                amount_msats=round(amount * receiving_currency.millisatoshi_per_unit),
            ),
            payer_node_pubkey=node.public_key,
            payer_utxos=node.uma_prescreening_utxos,
            utxo_callback=self.config.get_complete_url(
                "/api/uma/utxoCallback?txid=12345"
            ),
        )

        requested_payee_data = create_counterparty_data_options(
            {
                "compliance": True,
                "identifier": True,
                "email": False,
                "name": False,
            }
        )
        payreq = create_pay_request(
            currency_code=receiving_currency_code,
            amount=amount,
            payer_identifier=user.get_uma_address(self.config),
            payer_name=user.name,
            payer_email=user.email_address,
            payer_compliance=payer_compliance,
            requested_payee_data=requested_payee_data,
        )

        res = requests.post(
            initial_request_data.lnurlp_response.callback,
            json=payreq.to_dict(),
            timeout=20,
        )

        if res.status_code != 200:
            _abort_with_error(
                424, f"Error sending pay request: {res.status_code} {res.text}"
            )

        payreq_response: PayReqResponse
        try:
            payreq_response = parse_pay_req_response(res.text)
        except Exception as e:
            _abort_with_error(424, f"Error parsing pay request response: {e}")

        compliance = compliance_from_payee_data(payreq_response.payee_data)
        if not compliance:
            _abort_with_error(424, "No compliance data in pay request response.")

        if not self.compliance_service.pre_screen_transaction(
            sending_uma_address=user.get_uma_address(self.config),
            receiving_uma_address=initial_request_data.receiver_uma,
            amount_msats=round(amount * payreq_response.payment_info.multiplier)
            + payreq_response.payment_info.exchange_fees_msats,
            counterparty_node_id=compliance.node_pubkey,
            counterparty_utxos=compliance.utxos,
        ):
            _abort_with_error(403, "Transaction is not allowed.")

        sender_currencies = [
            CURRENCIES[currency]
            for currency in user.currencies
            if currency in CURRENCIES
        ]

        invoice_data = self.lightspark_client.get_decoded_payment_request(
            payreq_response.encoded_invoice
        )

        new_callback_uuid = self.request_cache.save_pay_req_data(
            encoded_invoice=payreq_response.encoded_invoice,
            utxo_callback=compliance.utxo_callback,
            invoice_data=invoice_data,
            sender_currencies=sender_currencies,
            sending_user_id=user.id,
            receiving_node_pubkey=compliance.node_pubkey,
        )

        return {
            "senderCurrencies": [currency.to_dict() for currency in sender_currencies],
            "callbackUuid": new_callback_uuid,
            "encodedInvoice": payreq_response.encoded_invoice,
            "amountMsats": invoice_data.amount.original_value,
            "conversionRate": payreq_response.payment_info.multiplier,
            "exchangeFeesMsats": payreq_response.payment_info.exchange_fees_msats,
            "currencyCode": payreq_response.payment_info.currency_code,
        }

    def handle_send_payment(self, callback_uuid: str):
        if not callback_uuid or not callback_uuid.strip():
            _abort_with_error(400, "Callback UUID is required.")

        user = self._get_calling_user_or_abort()
        payreq_data = self.request_cache.get_pay_req_data(callback_uuid)
        if not payreq_data:
            _abort_with_error(404, f"Cannot find callback UUID {callback_uuid}")
        if payreq_data.sending_user_id != user.id:
            _abort_with_error(403, "You are not authorized to send this payment.")

        is_invoice_expired = (
            payreq_data.invoice_data.expires_at.timestamp() < datetime.now().timestamp()
        )
        if is_invoice_expired:
            _abort_with_error(400, "Invoice has expired.")

        # TODO: Handle sending currencies besides SATs here and simulate the exchange.

        self._load_signing_key()
        payment_result = self.lightspark_client.pay_uma_invoice(
            node_id=self.config.node_id,
            encoded_invoice=payreq_data.encoded_invoice,
            timeout_secs=30,
            maximum_fees_msats=1000,
        )
        if not payment_result:
            _abort_with_error(500, "Payment failed.")
        payment = self.wait_for_payment_completion(payment_result)
        if payment.status != TransactionStatus.SUCCESS:
            _abort_with_error(
                500,
                f"Payment failed. Payment ID: {payment.id}",
            )

        self.compliance_service.register_transaction_monitoring(
            payment_id=payment.id,
            node_pubkey=payreq_data.receiving_node_pubkey,
            payment_direction=PaymentDirection.SENT,
            last_hop_utxos_with_amounts=payment.uma_post_transaction_data or [],
        )

        self._send_post_tx_callback(payment, payreq_data.utxo_callback)

        return "OK"

    def _parse_and_validate_amount(
        self, amount_str: str, currency_code: str, lnurlp_response: LnurlpResponse
    ) -> int:
        if not amount_str:
            _abort_with_error(400, "Amount in required.")

        amount: int
        try:
            amount = int(amount_str)
        except ValueError:
            _abort_with_error(400, "Amount must be an integer.")

        target_currency = next(
            (
                currency
                for currency in lnurlp_response.currencies
                if currency.code == currency_code
            ),
            None,
        )
        if not target_currency:
            _abort_with_error(
                400,
                f"Currency code {currency_code} is not supported.",
            )

        if (
            amount < target_currency.min_sendable
            or amount > target_currency.max_sendable
        ):
            _abort_with_error(
                400,
                f"Amount is out of range. Must be between {target_currency.min_sendable} and {target_currency.max_sendable}. Amount was {amount}.",
            )

        return amount

    def _get_calling_user_or_abort(self) -> User:
        user = self.user_service.get_calling_user_from_request(
            flask_request.url, flask_request.headers
        )
        if not user:
            _abort_with_error(401, "Unauthorized")
        return user

    def _send_post_tx_callback(self, payment: OutgoingPayment, utxo_callback: str):
        if not utxo_callback:
            return

        post_tx_data = payment.uma_post_transaction_data
        if not post_tx_data:
            print("No UTXO data to send.")
            return

        utxos: List[UtxoWithAmount] = []
        for output in post_tx_data:
            utxos.append(
                UtxoWithAmount(
                    utxo=output.utxo,
                    amount_msats=output.amount.convert_to(
                        CurrencyUnit.MILLISATOSHI
                    ).preferred_currency_value_rounded,
                )
            )

        res = requests.post(
            utxo_callback,
            json={"utxos": utxos},
            timeout=10,
        )
        if res.status_code != 200:
            # Allowing this to fail silently for now since it doesn't block the user flow.
            print(
                f"Error sending UTXO callback: {res.status_code} {res.text}",
                flush=True,
            )

    def _load_signing_key(self):
        node = get_node(self.lightspark_client, self.config.node_id)

        if "OSK" in node.typename:
            osk_password = self.config.osk_node_signing_key_password
            if not osk_password:
                _abort_with_error(
                    400,
                    "OSK password is required for OSK nodes.",
                )
            self.lightspark_client.recover_node_signing_key(
                self.config.node_id, osk_password
            )
            return

        # Assume remote signing.
        master_seed = self.config.get_remote_signing_node_master_seed()
        if not master_seed:
            _abort_with_error(
                400, "Remote signing master seed is required for remote signing nodes."
            )
        self.lightspark_client.provide_node_master_seed(
            self.config.node_id, master_seed, node.bitcoin_network
        )

    def wait_for_payment_completion(
        self, initial_payment: OutgoingPayment
    ) -> OutgoingPayment:
        max_retries = 40
        num_retries = 0
        payment = initial_payment
        while payment.status == TransactionStatus.PENDING and num_retries < max_retries:
            payment = self.lightspark_client.get_entity(payment.id, OutgoingPayment)
            if not payment:
                _abort_with_error(500, "Payment not found.")
            if payment.status == TransactionStatus.PENDING:
                time.sleep(0.25)
            num_retries += 1
        return payment


def _abort_with_error(status_code: int, reason: str) -> NoReturn:
    print(f"Aborting with error {status_code}: {reason}")
    abort(
        status_code,
        {
            "status": "ERROR",
            "reason": reason,
        },
    )


def register_routes(app: Flask, sending_vasp: SendingVasp):
    @app.route("/api/umalookup/<receiver_uma>")
    def handle_uma_lookup(receiver_uma: str):
        return sending_vasp.handle_uma_lookup(receiver_uma)

    @app.route("/api/umapayreq/<callback_uuid>")
    def handle_uma_payreq(callback_uuid: str):
        return sending_vasp.handle_uma_payreq(callback_uuid)

    @app.route("/api/sendpayment/<callback_uuid>", methods=["POST"])
    def handle_send_payment(callback_uuid: str):
        return sending_vasp.handle_send_payment(callback_uuid)
