import time
from builtins import len
from datetime import datetime
from typing import List, NoReturn, Optional
from urllib.parse import urljoin

import requests
from flask import Flask, current_app
from flask import request as flask_request
from lightspark import CurrencyUnit
from lightspark.utils.currency_amount import amount_as_msats
from lightspark import LightsparkSyncClient as LightsparkClient
from lightspark import OutgoingPayment, PaymentDirection, TransactionStatus
from uma import (
    Currency,
    INonceCache,
    InvalidSignatureException,
    Invoice,
    IPublicKeyCache,
    LnurlpResponse,
    ParsedVersion,
    PayReqResponse,
    UtxoWithAmount,
    create_compliance_payer_data,
    create_counterparty_data_options,
    create_pay_request,
    create_post_transaction_callback,
    create_uma_lnurlp_request_url,
    fetch_public_key_for_vasp,
    is_domain_local,
    none_throws,
    parse_lnurlp_response,
    parse_pay_req_response,
    select_highest_supported_version,
    verify_pay_req_response_signature,
    verify_uma_invoice_signature,
    verify_uma_lnurlp_response_signature,
)

from uma_vasp.address_helpers import get_domain_from_uma_address
from uma_vasp.compliance_service import IComplianceService
from uma_vasp.config import Config
from uma_vasp.currencies import CURRENCIES
from uma_vasp.lightspark_helpers import get_node
from uma_vasp.sending_vasp_request_cache import (
    ISendingVaspRequestCache,
    SendingVaspInitialRequestData,
)
from uma_vasp.uma_exception import UmaException
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
        nonce_cache: INonceCache,
    ) -> None:
        self.user_service = user_service
        self.compliance_service = compliance_service
        self.vasp_pubkey_cache = pubkey_cache
        self.lightspark_client = lightspark_client
        self.request_cache = request_cache
        self.config = config
        self.nonce_cache = nonce_cache

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

        url = (
            create_uma_lnurlp_request_url(
                signing_private_key=self.config.get_signing_privkey(),
                receiver_address=receiver_uma,
                sender_vasp_domain=self.config.get_uma_domain(),
                is_subject_to_travel_rule=True,
            )
            if receiver_uma.startswith("$")
            else self._create_non_uma_lnurlp_request_url(receiver_uma)
        )
        print(f"Fetching LNURLP as {url}", flush=True)

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

        if not lnurlp_response.is_uma_response():
            print("Handling as regular LNURLP response:" + response.text, flush=True)
            return self._handle_as_non_uma_lnurl_response(lnurlp_response, receiver_uma)

        receiver_vasp_pubkey = fetch_public_key_for_vasp(
            vasp_domain=get_domain_from_uma_address(receiver_uma),
            cache=self.vasp_pubkey_cache,
        )

        # Skip signature verification in testing mode to avoid needing to run 2 VASPs.
        is_testing = current_app.config.get("TESTING", False)
        if not is_testing:
            try:
                verify_uma_lnurlp_response_signature(
                    lnurlp_response, receiver_vasp_pubkey, self.nonce_cache
                )
            except InvalidSignatureException as e:
                _abort_with_error(
                    424, f"Error verifying LNURLP response signature: {e}"
                )

        callback_uuid = self.request_cache.save_lnurlp_response_data(
            lnurlp_response=lnurlp_response, receiver_uma=receiver_uma
        )
        sender_currencies = [
            CURRENCIES[currency]
            for currency in user.currencies
            if currency in CURRENCIES
        ]

        return {
            "senderCurrencies": [currency.to_dict() for currency in sender_currencies],
            "receiverCurrencies": (
                [currency.to_dict() for currency in lnurlp_response.currencies]
                if lnurlp_response.currencies
                else [CURRENCIES["SAT"].to_dict()]
            ),
            "minSendableSats": lnurlp_response.min_sendable,
            "maxSendableSats": lnurlp_response.max_sendable,
            "callbackUuid": callback_uuid,
            # You might not actually send this to a client in practice.
            "receiverKycStatus": (
                lnurlp_response.compliance.kyc_status.value
                if lnurlp_response.compliance
                else None
            ),
        }

    def _create_non_uma_lnurlp_request_url(self, receiver_address: str) -> str:
        receiver_address_parts = receiver_address.split("@")
        if len(receiver_address_parts) != 2:
            _abort_with_error(400, "Invalid non-UMA receiver address.")
        scheme = "http" if is_domain_local(receiver_address_parts[1]) else "https"
        url_path = f"/.well-known/lnurlp/{receiver_address_parts[0]}"
        return urljoin(f"{scheme}://{receiver_address_parts[1]}", url_path)

    def _handle_as_non_uma_lnurl_response(
        self, lnurlp_response: LnurlpResponse, receiver_uma: str
    ):
        user = self._get_calling_user_or_abort()
        callback_uuid = self.request_cache.save_lnurlp_response_data(
            lnurlp_response=lnurlp_response, receiver_uma=receiver_uma
        )
        sender_currencies = [
            CURRENCIES[currency]
            for currency in user.currencies
            if currency in CURRENCIES
        ]
        return {
            "senderCurrencies": [currency.to_dict() for currency in sender_currencies],
            "receiverCurrencies": (
                [currency.to_dict() for currency in lnurlp_response.currencies]
                if lnurlp_response.currencies
                else [CURRENCIES["SAT"].to_dict()]
            ),
            "minSendableSats": lnurlp_response.min_sendable,
            "maxSendableSats": lnurlp_response.max_sendable,
            "callbackUuid": callback_uuid,
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
        retry_url = create_uma_lnurlp_request_url(
            signing_private_key=self.config.get_signing_privkey(),
            receiver_address=receiver_uma,
            sender_vasp_domain=self.config.get_uma_domain(),
            is_subject_to_travel_rule=True,
            uma_version_override=new_version,
        )
        return requests.get(retry_url, timeout=20)

    def handle_pay_invoice(self):
        user = self._get_calling_user_or_abort()

        invoice_string = flask_request.json.get("invoice")
        if not invoice_string:
            _abort_with_error(400, "Invoice is required.")

        if not invoice_string.startswith("uma1"):
            invoice_string = self.uma_request_storage.get_request(invoice_string)[
                "invoice_string"
            ]

        invoice = Invoice.from_bech32_string(invoice_string)
        if not invoice:
            _abort_with_error(400, "Invalid invoice.")

        receiver_uma = invoice.receiver_uma
        receiving_domain = get_domain_from_uma_address(receiver_uma)
        receiver_vasp_pubkey = fetch_public_key_for_vasp(
            vasp_domain=receiving_domain,
            cache=self.vasp_pubkey_cache,
        )
        print(f"Signature: {invoice.signature.hex()}")
        verify_uma_invoice_signature(invoice, receiver_vasp_pubkey)

        receiving_currency = CURRENCIES[invoice.receving_currency.code]

        return self._handle_internal_uma_payreq(
            receiver_uma=receiver_uma,
            callback=invoice.callback,
            amount=invoice.amount,
            is_amount_in_msats=receiving_currency.code == "SAT",
            receiving_currency=receiving_currency,
            user_id=user.id,
            uma_version=invoice.uma_version,
            invoice_uuid=invoice.invoice_uuid,
        ).to_json()

    def handle_uma_payreq(self, callback_uuid: str):
        user = self._get_calling_user_or_abort()

        initial_request_data = self.request_cache.get_lnurlp_response_data(
            callback_uuid
        )
        if initial_request_data is None:
            _abort_with_error(404, f"Cannot find callback UUID {callback_uuid}")

        receiving_currency_code = flask_request.args.get("receivingCurrencyCode", "SAT")

        is_amount_in_msats = (
            flask_request.args.get("isAmountInMsats", "").lower() == "true"
        )
        receiving_currencies = initial_request_data.lnurlp_response.currencies or [
            CURRENCIES["SAT"]
        ]
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
            "SAT" if is_amount_in_msats else receiving_currency_code,
            initial_request_data.lnurlp_response,
        )

        if not initial_request_data.lnurlp_response.is_uma_response():
            return self._handle_as_non_uma_payreq(
                initial_request_data,
                amount,
                receiving_currency_code,
                is_amount_in_msats,
            )

        receiver_uma = initial_request_data.receiver_uma
        callback = initial_request_data.lnurlp_response.callback
        uma_version = initial_request_data.lnurlp_response.uma_version
        return self._handle_internal_uma_payreq(
            receiver_uma,
            callback,
            amount,
            is_amount_in_msats,
            receiving_currency,
            user.id,
            uma_version,
        )

    def _handle_internal_uma_payreq(
        self,
        receiver_uma: str,
        callback: str,
        amount: int,
        is_amount_in_msats: bool,
        receiving_currency: Currency,
        user_id: str,
        uma_version: str,
        invoice_uuid: Optional[str] = None,
    ):
        user = User.from_id(user_id)

        receiving_domain = get_domain_from_uma_address(receiver_uma)
        receiver_vasp_pubkey = fetch_public_key_for_vasp(
            vasp_domain=receiving_domain,
            cache=self.vasp_pubkey_cache,
        )

        node = get_node(self.lightspark_client, self.config.node_id)

        payer_compliance = create_compliance_payer_data(
            receiver_encryption_pubkey=receiver_vasp_pubkey.get_encryption_pubkey(),
            signing_private_key=self.config.get_signing_privkey(),
            payer_identifier=user.get_uma_address(self.config),
            payer_kyc_status=user.kyc_status,
            travel_rule_info=self.compliance_service.get_travel_rule_info_for_transaction(
                sending_user_id=user.id,
                sending_uma_address=user.get_uma_address(self.config),
                receiving_uma_address=receiver_uma,
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
        if uma_version is not None:
            uma_version = ParsedVersion.load(uma_version).major
        print(f"Payreq using UMA version {uma_version}")
        payreq = create_pay_request(
            receiving_currency_code=receiving_currency.code,
            is_amount_in_receiving_currency=not is_amount_in_msats,
            amount=amount,
            payer_identifier=user.get_uma_address(self.config),
            payer_name=user.name,
            payer_email=user.email_address,
            payer_compliance=payer_compliance,
            requested_payee_data=requested_payee_data,
            uma_major_version=uma_version if uma_version is not None else 1,
        )
        print(f"Payreq: {payreq.to_dict()}", flush=True)

        res = requests.post(
            callback,
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

        if not payreq_response.is_uma_response():
            _abort_with_error(424, "Response to UMA payreq is not a UMA response.")

        compliance = none_throws(payreq_response.get_compliance())
        if not compliance:
            _abort_with_error(424, "No compliance data in pay request response.")

        print(f"payreq_response: {payreq_response.to_dict()}")
        if uma_version == 1:
            try:
                verify_pay_req_response_signature(
                    user.get_uma_address(self.config),
                    receiver_uma,
                    payreq_response,
                    receiver_vasp_pubkey,
                    self.nonce_cache,
                )
            except InvalidSignatureException as e:
                _abort_with_error(
                    424, f"Error verifying payreq response signature: {e}"
                )

        payment_info = none_throws(payreq_response.payment_info)
        if not self.compliance_service.pre_screen_transaction(
            sending_uma_address=user.get_uma_address(self.config),
            receiving_uma_address=receiver_uma,
            amount_msats=round(amount * payment_info.multiplier)
            + payment_info.exchange_fees_msats,
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
            "amountMsats": amount_as_msats(invoice_data.amount),
            "conversionRate": payment_info.multiplier,
            "exchangeFeesMsats": payment_info.exchange_fees_msats,
            "receivingCurrencyCode": payment_info.currency_code,
            "amountReceivingCurrency": payment_info.amount,
        }

    def _handle_as_non_uma_payreq(
        self,
        initial_request_data: SendingVaspInitialRequestData,
        amount: int,
        receiving_currency_code: str,
        is_amount_in_msats: bool,
    ):
        user = self._get_calling_user_or_abort()
        sender_currencies = [
            CURRENCIES[currency]
            for currency in user.currencies
            if currency in CURRENCIES
        ]

        payreq = create_pay_request(
            receiving_currency_code=receiving_currency_code,
            is_amount_in_receiving_currency=not is_amount_in_msats,
            amount=amount,
            payer_identifier=user.get_non_uma_lnurl_address(self.config),
            payer_name=None,
            payer_email=None,
            payer_compliance=None,
            requested_payee_data=None,
            uma_major_version=1,  # Use the new LUD-21 fields.
        )

        res = requests.get(
            initial_request_data.lnurlp_response.callback,
            params=payreq.to_request_params(),
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

        invoice_data = self.lightspark_client.get_decoded_payment_request(
            payreq_response.encoded_invoice
        )

        new_callback_uuid = self.request_cache.save_pay_req_data(
            encoded_invoice=payreq_response.encoded_invoice,
            utxo_callback="",
            invoice_data=invoice_data,
            sender_currencies=sender_currencies,
            sending_user_id=user.id,
            receiving_node_pubkey=None,
        )

        return {
            "senderCurrencies": [currency.to_dict() for currency in sender_currencies],
            "callbackUuid": new_callback_uuid,
            "encodedInvoice": payreq_response.encoded_invoice,
            "amountMsats": invoice_data.amount.original_value,
            "conversionRate": (
                payreq_response.payment_info.multiplier
                if payreq_response.payment_info
                else 1
            ),
            "exchangeFeesMsats": (
                payreq_response.payment_info.exchange_fees_msats
                if payreq_response.payment_info
                else 0
            ),
            "currencyCode": (
                payreq_response.payment_info.currency_code
                if payreq_response.payment_info
                else "SAT"
            ),
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
            signing_private_key=self.config.get_signing_privkey(),
            sender_identifier=user.get_uma_address(
                self.config
            ),  # hashed with a monthly rotated seed and used for anonymized analysis
        )
        if not payment_result:
            _abort_with_error(500, "Payment failed.")
        payment = self.wait_for_payment_completion(payment_result)
        if payment.status != TransactionStatus.SUCCESS:
            _abort_with_error(
                500,
                f"Payment failed. Payment ID: {payment.id}",
            )
        if payreq_data.receiving_node_pubkey or payment.uma_post_transaction_data:
            self.compliance_service.register_transaction_monitoring(
                payment_id=payment.id,
                node_pubkey=payreq_data.receiving_node_pubkey,
                payment_direction=PaymentDirection.SENT,
                last_hop_utxos_with_amounts=payment.uma_post_transaction_data or [],
            )

        if payreq_data.utxo_callback:
            self._send_post_tx_callback(payment, payreq_data.utxo_callback)

        return {
            "paymentId": payment.id,
            "status": payment.status.value,
        }

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

        # add SATS for sender-locked if not present:
        currencies = lnurlp_response.currencies or []
        if not any(currency.code == "SAT" for currency in currencies):
            sat_currency = CURRENCIES["SAT"]
            sat_currency.min_sendable = lnurlp_response.min_sendable
            sat_currency.max_sendable = lnurlp_response.max_sendable
            currencies.append(sat_currency)

        target_currency = next(
            (currency for currency in currencies if currency.code == currency_code),
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

        post_tx_callback = create_post_transaction_callback(
            utxos, self.config.get_uma_domain(), self.config.get_signing_privkey()
        )

        res = requests.post(
            utxo_callback,
            json=post_tx_callback.to_dict(),
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
    raise UmaException(reason, status_code)


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

    @app.route("/api/uma/pay_invoice", methods=["POST"])
    def handle_pay_invoice():
        return sending_vasp.handle_pay_invoice()
