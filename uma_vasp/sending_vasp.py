from typing import cast
import requests
from flask import abort
from flask import request as flask_request
from lightspark import (
    LightsparkSyncClient as LightsparkClient,
    InvoiceData,
)
from uma import (
    InvalidSignatureException,
    IPublicKeyCache,
    LnurlpResponse,
    PayReqResponse,
    create_compliance_payer_data,
    create_lnurlp_request_url,
    create_pay_request,
    fetch_public_key_for_vasp,
    parse_lnurlp_response,
    parse_pay_req_response,
    verify_uma_lnurlp_response_signature,
)
from uma_vasp.address_helpers import get_domain_from_uma_address

from uma_vasp.app import app
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
        lightspark_client: LightsparkClient,
        pubkey_cache: IPublicKeyCache,
        request_cache: ISendingVaspRequestCache,
        config: Config,
    ) -> None:
        self.user_service = user_service
        self.vasp_pubkey_cache = pubkey_cache
        self.lightspark_client = lightspark_client
        self.request_cache = request_cache
        self.config = config

    def handle_uma_lookup(self, receiver_uma: str):
        user = self._get_calling_user_or_abort()

        url = create_lnurlp_request_url(
            signing_private_key=self.config.get_signing_privkey(),
            receiver_address=receiver_uma,
            sender_vasp_domain=self.config.get_uma_domain(),
            is_subject_to_travel_rule=True,
        )

        response = requests.get(url, timeout=20)
        # TODO: Add version negotiation handling.
        if response.status_code != 200:
            abort(
                424,
                {
                    "status": "ERROR",
                    "reason": f"Error fetching LNURLP: {response.status_code} {response.text}",
                },
            )

        lnurlp_response: LnurlpResponse
        try:
            lnurlp_response = parse_lnurlp_response(response.text)
        except Exception as e:
            abort(
                424,
                {
                    "status": "ERROR",
                    "reason": f"Error parsing LNURLP response: {e}",
                },
            )

        receiver_vasp_pubkey = fetch_public_key_for_vasp(
            vasp_domain=get_domain_from_uma_address(receiver_uma),
            cache=self.vasp_pubkey_cache,
        )

        try:
            verify_uma_lnurlp_response_signature(
                lnurlp_response, receiver_vasp_pubkey.signing_pubkey
            )
        except InvalidSignatureException as e:
            abort(
                424,
                {
                    "status": "ERROR",
                    "reason": f"Error verifying LNURLP response signature: {e}",
                },
            )

        callback_uuid = self.request_cache.save_lnurlp_response_data(
            lnurlp_response=lnurlp_response,
            receiver_id=user.id,
            receiving_vasp_domain=self.config.get_uma_domain(),
        )
        sender_currencies = [
            CURRENCIES[currency]
            for currency in user.currencies
            if currency in CURRENCIES
        ]

        return {
            "senderCurrencies": sender_currencies,
            "receiverCurrencies": lnurlp_response.currencies,
            "minSendableSats": lnurlp_response.min_sendable,
            "maxSendableSats": lnurlp_response.max_sendable,
            "callbackUuid": callback_uuid,
            # You might not actually send this to a client in practice.
            "receiverKycStatus": lnurlp_response.compliance.kyc_status.value,
        }

    def handle_uma_payreq(self, callback_uuid: str):
        user = self._get_calling_user_or_abort()

        initial_request_data = self.request_cache.get_lnurlp_response_data(
            callback_uuid
        )
        if not initial_request_data:
            abort(
                404,
                {
                    "status": "ERROR",
                    "reason": f"Cannot find callback UUID {callback_uuid}",
                },
            )

        receiving_currency_code = flask_request.args.get("currencyCode")
        if not receiving_currency_code:
            abort(
                400,
                {
                    "status": "ERROR",
                    "reason": "Currency code is required.",
                },
            )

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
            abort(
                400,
                {
                    "status": "ERROR",
                    "reason": "Currency code is not supported.",
                },
            )

        amount = self._parse_and_validate_amount(
            flask_request.args.get("amount"),
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
            travel_rule_info=None,
            payer_node_pubkey=node.public_key,
            payer_utxos=node.uma_prescreening_utxos,
            utxo_callback=self.config.get_complete_url(
                "/api/uma/utxoCallback?txid=12345"
            ),
        )

        payreq = create_pay_request(
            currency_code=receiving_currency_code,
            amount=amount,
            payer_identifier=user.get_uma_address(self.config),
            payer_name=user.name,
            payer_email=user.email_address,
            payer_compliance=payer_compliance,
        )

        res = requests.post(
            initial_request_data.lnurlp_response.callback,
            json=payreq.to_dict(),
            timeout=20,
        )

        if res.status_code != 200:
            abort(
                424,
                {
                    "status": "ERROR",
                    "reason": f"Error sending pay request: {res.status_code} {res.text}",
                },
            )

        payreq_response: PayReqResponse
        try:
            payreq_response = parse_pay_req_response(res.text)
        except Exception as e:
            abort(
                424,
                {
                    "status": "ERROR",
                    "reason": f"Error parsing pay request response: {e}",
                },
            )

        sender_currencies = [
            CURRENCIES[currency]
            for currency in user.currencies
            if currency in CURRENCIES
        ]

        invoice_data = cast(
            InvoiceData,
            self.lightspark_client.get_decoded_payment_request(
                payreq_response.encoded_invoice
            ),
        )

        new_callback_uuid = self.request_cache.save_pay_req_data(
            encoded_invoice=payreq_response.encoded_invoice,
            utxo_callback=payreq_response.compliance.utxo_callback,
            invoice_data=invoice_data,
            sender_currencies=sender_currencies,
        )

        return {
            "senderCurrencies": sender_currencies,
            "callbackUuid": new_callback_uuid,
            "encodedInvoice": payreq_response.encoded_invoice,
            "amountMsats": invoice_data.amount.original_value,
            "conversionRate": payreq_response.payment_info.multiplier,
            "exchangeFeesMsats": payreq_response.payment_info.exchange_fees_msats,
            "currencyCode": payreq_response.payment_info.currency_code,
        }

    def handle_send_payment(self, callback_uuid: str):
        return "OK"

    def _parse_and_validate_amount(
        self, amount_str: str, currency_code: str, lnurlp_response: LnurlpResponse
    ) -> int:
        if not amount_str:
            abort(
                400,
                {
                    "status": "ERROR",
                    "reason": "Amount is required.",
                },
            )

        amount: int
        try:
            amount = int(amount_str)
        except ValueError:
            abort(
                400,
                {
                    "status": "ERROR",
                    "reason": "Amount must be an integer.",
                },
            )

        target_currency = next(
            (
                currency
                for currency in lnurlp_response.currencies
                if currency.code == currency_code
            ),
            None,
        )
        if not target_currency:
            abort(
                400,
                {
                    "status": "ERROR",
                    "reason": "Currency code is not supported.",
                },
            )

        if (
            amount < target_currency.min_sendable
            or amount > target_currency.max_sendable
        ):
            abort(
                400,
                {
                    "status": "ERROR",
                    "reason": f"Amount is out of range. Must be between {target_currency.min_sendable} and {target_currency.max_sendable}. Amount was {amount}.",
                },
            )

        return amount

    def _get_calling_user_or_abort(self) -> User:
        user = self.user_service.get_calling_user_from_request(
            flask_request.url, flask_request.headers
        )
        if not user:
            abort(401)
        return user


def register_routes(sending_vasp: SendingVasp):
    @app.route("/api/umalookup/<receiver_uma>")
    def handle_uma_lookup(receiver_uma: str):
        return sending_vasp.handle_uma_lookup(receiver_uma)

    @app.route("/api/umapayreq/<callback_uuid>")
    def handle_uma_payreq(callback_uuid: str):
        return sending_vasp.handle_uma_payreq(callback_uuid)

    @app.route("/api/sendpayment/<callback_uuid>", methods=["POST"])
    def handle_send_payment(callback_uuid: str):
        return sending_vasp.handle_send_payment(callback_uuid)
