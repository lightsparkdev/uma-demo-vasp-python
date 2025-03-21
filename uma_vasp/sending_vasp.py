import time
from builtins import len
from datetime import datetime
from typing import List, Optional
from urllib.parse import urljoin

import requests
from flask import Flask, Response, current_app
from flask import request as flask_request
from lightspark import CurrencyUnit
from lightspark import LightsparkSyncClient as LightsparkClient
from lightspark import OutgoingPayment, PaymentDirection, TransactionStatus
from lightspark.utils.currency_amount import amount_as_msats
from uma import (
    Currency,
    ErrorCode,
    INonceCache,
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
from uma_vasp.flask_helpers import abort_with_error
from uma_vasp.lightspark_helpers import get_node, load_signing_key
from uma_vasp.request_storage import IRequestStorage
from uma_vasp.sending_vasp_payreq_response import SendingVaspPayReqResponse
from uma_vasp.sending_vasp_request_cache import (
    ISendingVaspRequestCache,
    SendingVaspInitialRequestData,
)
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
        uma_request_storage: IRequestStorage,
    ) -> None:
        self.user_service = user_service
        self.compliance_service = compliance_service
        self.vasp_pubkey_cache = pubkey_cache
        self.lightspark_client = lightspark_client
        self.request_cache = request_cache
        self.config = config
        self.nonce_cache = nonce_cache
        self.uma_request_storage = uma_request_storage

    def handle_uma_lookup(self, receiver_uma: str):
        user = self._get_calling_user_or_abort()

        if not self.compliance_service.should_accept_transaction_to_vasp(
            receiving_vasp_domain=get_domain_from_uma_address(receiver_uma),
            sending_uma_address=user.get_uma_address(self.config),
            receiving_uma_address=receiver_uma,
        ):
            abort_with_error(
                "Transactions to that receiving VASP are not allowed.",
                ErrorCode.COUNTERPARTY_NOT_ALLOWED,
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
            abort_with_error(
                f"Error fetching LNURLP: {response.status_code} {response.text}",
                ErrorCode.LNURLP_REQUEST_FAILED,
            )

        lnurlp_response: LnurlpResponse
        try:
            lnurlp_response = parse_lnurlp_response(response.text)
        except Exception as e:
            abort_with_error(
                f"Error parsing LNURLP response: {e}",
                ErrorCode.PARSE_LNURLP_RESPONSE_ERROR,
            )

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
            verify_uma_lnurlp_response_signature(
                lnurlp_response, receiver_vasp_pubkey, self.nonce_cache
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
            abort_with_error(
                "Invalid non-UMA receiver address.", ErrorCode.INVALID_INPUT
            )
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
            abort_with_error(
                "No major versions supported by receiving VASP.",
                ErrorCode.NO_COMPATIBLE_UMA_VERSION,
            )
        new_version = select_highest_supported_version(supported_major_versions)
        if not new_version:
            abort_with_error(
                "No matching UMA version compatible with receiving VASP.",
                ErrorCode.NO_COMPATIBLE_UMA_VERSION,
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
        if not flask_request.json:
            abort_with_error(
                "Request body is required", ErrorCode.MISSING_REQUIRED_UMA_PARAMETERS
            )

        invoice_string = flask_request.json.get("invoice")
        if not invoice_string:
            abort_with_error(
                "Invoice is required.", ErrorCode.MISSING_REQUIRED_UMA_PARAMETERS
            )

        if not invoice_string.startswith("uma1"):
            invoice_string = self.uma_request_storage.get_request(invoice_string)[
                "invoice_string"
            ]

        invoice = Invoice.from_bech32_string(invoice_string)
        if not invoice:
            abort_with_error(400, "Invalid invoice.")

        receiver_uma = invoice.receiver_uma
        receiving_domain = get_domain_from_uma_address(receiver_uma)
        receiver_vasp_pubkey = fetch_public_key_for_vasp(
            vasp_domain=receiving_domain,
            cache=self.vasp_pubkey_cache,
        )

        # Skip signature verification in testing mode to avoid needing to run 2 VASPs.
        is_testing = current_app.config.get("TESTING", False)
        if not is_testing:
            verify_uma_invoice_signature(invoice, receiver_vasp_pubkey)

        receiving_currency = CURRENCIES[invoice.receving_currency.code]

        version_strs = invoice.uma_versions.split(",")
        major_versions = [
            ParsedVersion.load(uma_version).major for uma_version in version_strs
        ]
        highest_version = select_highest_supported_version(major_versions)

        return self._handle_internal_uma_payreq(
            receiver_uma=receiver_uma,
            callback=invoice.callback,
            amount=invoice.amount,
            is_amount_in_msats=receiving_currency.code == "SAT",
            receiving_currency=receiving_currency,
            user_id=user.id,
            uma_version=highest_version,
            invoice_uuid=invoice.invoice_uuid,
        ).to_json()

    def handle_uma_payreq_request(self, callback_uuid: str):
        user = self._get_calling_user_or_abort()
        receiving_currency_code = flask_request.args.get("receivingCurrencyCode", "SAT")

        initial_request_data = self.request_cache.get_lnurlp_response_data(
            callback_uuid
        )
        if initial_request_data is None:
            abort_with_error(
                f"Cannot find callback UUID {callback_uuid}",
                ErrorCode.REQUEST_NOT_FOUND,
            )
        is_amount_in_msats = (
            flask_request.args.get("isAmountInMsats", "").lower() == "true"
        )
        amount = self._parse_and_validate_amount(
            flask_request.args.get("amount", ""),
            "SAT" if is_amount_in_msats else receiving_currency_code,
            initial_request_data.lnurlp_response,
        )
        return self.handle_uma_payreq(
            callback_uuid,
            is_amount_in_msats,
            amount,
            receiving_currency_code,
            user,
        ).to_json()

    def handle_uma_payreq(
        self,
        callback_uuid: str,
        is_amount_in_msats: bool,
        amount: int,
        receiving_currency_code: str,
        user: User,
    ) -> SendingVaspPayReqResponse:
        initial_request_data = self.request_cache.get_lnurlp_response_data(
            callback_uuid
        )
        if initial_request_data is None:
            abort_with_error(
                f"Cannot find callback UUID {callback_uuid}",
                ErrorCode.REQUEST_NOT_FOUND,
            )

        receiving_currency_code = flask_request.args.get("receivingCurrencyCode", "SAT")

        # TODO: Handle sending currencies besides SATs here and simulate the exchange.
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
            abort_with_error(
                "Currency code is not supported.", ErrorCode.INVALID_CURRENCY
            )

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
        uma_version: Optional[str],
        invoice_uuid: Optional[str] = None,
    ):
        user = self.user_service.get_user_from_id(user_id)
        if not user:
            abort_with_error("Unauthorized", ErrorCode.USER_NOT_FOUND)

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
            parsed_uma_major_version = ParsedVersion.load(uma_version).major
        else:
            parsed_uma_major_version = None
        print(f"Payreq using UMA version {parsed_uma_major_version}")
        payreq = create_pay_request(
            receiving_currency_code=receiving_currency.code,
            is_amount_in_receiving_currency=not is_amount_in_msats,
            amount=amount,
            payer_identifier=user.get_uma_address(self.config),
            payer_name=user.name,
            payer_email=user.email_address,
            payer_compliance=payer_compliance,
            requested_payee_data=requested_payee_data,
            uma_major_version=(
                parsed_uma_major_version if parsed_uma_major_version is not None else 1
            ),
            invoice_uuid=invoice_uuid,
        )
        print(f"Payreq: {payreq.to_dict()}", flush=True)

        res = requests.post(
            callback,
            json=payreq.to_dict(),
            timeout=20,
        )

        if res.status_code != 200:
            abort_with_error(
                f"Error sending pay request: {res.status_code} {res.text}",
                ErrorCode.PAYREQ_REQUEST_FAILED,
            )

        payreq_response: PayReqResponse
        try:
            payreq_response = parse_pay_req_response(res.text)
        except Exception as e:
            abort_with_error(
                f"Error parsing pay request response: {e}",
                ErrorCode.PARSE_PAYREQ_RESPONSE_ERROR,
            )

        if not payreq_response.is_uma_response():
            abort_with_error(
                "Response to UMA payreq is not a UMA response.",
                ErrorCode.MISSING_REQUIRED_UMA_PARAMETERS,
            )

        compliance = none_throws(payreq_response.get_compliance())
        if not compliance:
            abort_with_error(
                "No compliance data in pay request response.",
                ErrorCode.MISSING_REQUIRED_UMA_PARAMETERS,
            )

        print(f"payreq_response: {payreq_response.to_dict()}")
        # Skip signature verification in testing mode to avoid needing to run 2 VASPs.
        is_testing = current_app.config.get("TESTING", False)
        if uma_version == 1 and not is_testing:
            verify_pay_req_response_signature(
                user.get_uma_address(self.config),
                receiver_uma,
                payreq_response,
                receiver_vasp_pubkey,
                self.nonce_cache,
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
            abort_with_error(
                "Transaction is not allowed.", ErrorCode.COUNTERPARTY_NOT_ALLOWED
            )

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

        amount_receiving_currency = (
            payreq_response.payment_info.amount
            if payreq_response.payment_info
            and payreq_response.payment_info.amount is not None
            else round(amount_as_msats(invoice_data.amount) / 1000)
        )

        return SendingVaspPayReqResponse(
            sender_currencies=sender_currencies,
            callback_uuid=new_callback_uuid,
            encoded_invoice=payreq_response.encoded_invoice,
            amount_msats=amount_as_msats(invoice_data.amount),
            conversion_rate=payment_info.multiplier,
            exchange_fees_msats=payment_info.exchange_fees_msats,
            receiving_currency_code=payment_info.currency_code,
            amount_receiving_currency=amount_receiving_currency,
            payment_hash=invoice_data.payment_hash,
            invoice_expires_at=round(invoice_data.expires_at.timestamp()),
            uma_invoice_uuid=None,
        )

    def _handle_as_non_uma_payreq(
        self,
        initial_request_data: SendingVaspInitialRequestData,
        amount: int,
        receiving_currency_code: str,
        is_amount_in_msats: bool,
    ) -> SendingVaspPayReqResponse:
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
            abort_with_error(
                f"Error sending pay request: {res.status_code} {res.text}",
                ErrorCode.PAYREQ_REQUEST_FAILED,
            )

        payreq_response: PayReqResponse
        try:
            payreq_response = parse_pay_req_response(res.text)
        except Exception as e:
            abort_with_error(
                f"Error parsing pay request response: {e}",
                ErrorCode.PARSE_PAYREQ_RESPONSE_ERROR,
            )

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

        return SendingVaspPayReqResponse(
            sender_currencies=sender_currencies,
            callback_uuid=new_callback_uuid,
            encoded_invoice=payreq_response.encoded_invoice,
            amount_msats=amount_as_msats(invoice_data.amount),
            conversion_rate=(
                payreq_response.payment_info.multiplier
                if payreq_response.payment_info
                else 1
            ),
            exchange_fees_msats=(
                payreq_response.payment_info.exchange_fees_msats
                if payreq_response.payment_info
                else 0
            ),
            receiving_currency_code=(
                payreq_response.payment_info.currency_code
                if payreq_response.payment_info
                else "SAT"
            ),
            amount_receiving_currency=(
                payreq_response.payment_info.amount
                if payreq_response.payment_info and payreq_response.payment_info.amount
                else amount_as_msats(invoice_data.amount)
            ),
            payment_hash=invoice_data.payment_hash,
            invoice_expires_at=round(invoice_data.expires_at.timestamp()),
            uma_invoice_uuid=None,
        )

    def handle_request_pay_invoice(self, invoice: Invoice):
        if not flask_request.json:
            abort_with_error(
                "Request body is required", ErrorCode.MISSING_REQUIRED_UMA_PARAMETERS
            )
        receiver_uma = invoice.receiver_uma
        receiving_domain = get_domain_from_uma_address(receiver_uma)
        receiver_vasp_pubkey = fetch_public_key_for_vasp(
            vasp_domain=receiving_domain,
            cache=self.vasp_pubkey_cache,
        )
        # Skip signature verification in testing mode to avoid needing to run 2 VASPs.
        is_testing = current_app.config.get("TESTING", False)
        if not is_testing:
            verify_uma_invoice_signature(invoice, receiver_vasp_pubkey)
        receiving_currency = CURRENCIES[invoice.receving_currency.code]
        if not receiving_currency:
            abort_with_error(
                "Currency code is not supported.", ErrorCode.INVALID_CURRENCY
            )

        info = {
            "amount": invoice.amount,
            "receiving_currency_code": invoice.receving_currency.code,
            "receiver_uma": receiver_uma,
            "invoice_string": flask_request.json.get("invoice"),
        }
        self.uma_request_storage.save_request(invoice.invoice_uuid, info)

        # notify the user that they have a payment request
        return Response(status=200)

    def handle_send_payment(self, callback_uuid: str):
        if not callback_uuid or not callback_uuid.strip():
            abort_with_error("Callback UUID is required.", ErrorCode.INVALID_INPUT)

        user = self._get_calling_user_or_abort()
        payreq_data = self.request_cache.get_pay_req_data(callback_uuid)
        if not payreq_data:
            abort_with_error(
                f"Cannot find callback UUID {callback_uuid}",
                ErrorCode.REQUEST_NOT_FOUND,
            )
        if payreq_data.sending_user_id != user.id:
            abort_with_error(
                "You are not authorized to send this payment.", ErrorCode.USER_NOT_FOUND
            )

        is_invoice_expired = (
            payreq_data.invoice_data.expires_at.timestamp() < datetime.now().timestamp()
        )
        if is_invoice_expired:
            abort_with_error("Invoice has expired.", ErrorCode.INVOICE_EXPIRED)

        # TODO: Handle sending currencies besides SATs here and simulate the exchange.

        load_signing_key(self.lightspark_client, self.config)
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
            abort_with_error("Payment failed.", ErrorCode.INTERNAL_ERROR)
        payment = self.wait_for_payment_completion(payment_result)
        if payment.status != TransactionStatus.SUCCESS:
            abort_with_error(
                f"Payment failed. Payment ID: {payment.id}",
                ErrorCode.INTERNAL_ERROR,
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

    def get_pending_uma_requests(self):
        return self.uma_request_storage.get_requests()

    def _parse_and_validate_amount(
        self, amount_str: str, currency_code: str, lnurlp_response: LnurlpResponse
    ) -> int:
        if not amount_str:
            abort_with_error(
                "Amount is required.", ErrorCode.MISSING_REQUIRED_UMA_PARAMETERS
            )

        amount: int
        try:
            amount = int(amount_str)
        except ValueError:
            abort_with_error(
                "Amount must be an integer.", ErrorCode.PARSE_PAYREQ_REQUEST_ERROR
            )

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
            abort_with_error(
                f"Currency code {currency_code} is not supported.",
                ErrorCode.INVALID_CURRENCY,
            )

        if (
            amount < target_currency.min_sendable
            or amount > target_currency.max_sendable
        ):
            abort_with_error(
                f"Amount is out of range. Must be between {target_currency.min_sendable} and {target_currency.max_sendable}. Amount was {amount}.",
                ErrorCode.AMOUNT_OUT_OF_RANGE,
            )

        return amount

    def _get_calling_user_or_abort(self) -> User:
        user = self.user_service.get_calling_user_from_request(
            flask_request.url, dict(flask_request.headers)
        )
        if not user:
            abort_with_error("Unauthorized", ErrorCode.USER_NOT_FOUND)
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

    def wait_for_payment_completion(
        self, initial_payment: OutgoingPayment
    ) -> OutgoingPayment:
        max_retries = 40
        num_retries = 0
        payment = initial_payment
        while payment.status == TransactionStatus.PENDING and num_retries < max_retries:
            payment = self.lightspark_client.get_entity(payment.id, OutgoingPayment)
            if not payment:
                abort_with_error("Payment not found.", ErrorCode.INTERNAL_ERROR)
            if payment.status == TransactionStatus.PENDING:
                time.sleep(0.25)
            num_retries += 1
        return payment


def register_routes(app: Flask, sending_vasp: SendingVasp):
    @app.route("/api/umalookup/<receiver_uma>")
    def handle_uma_lookup(receiver_uma: str):
        return sending_vasp.handle_uma_lookup(receiver_uma)

    @app.route("/api/umapayreq/<callback_uuid>")
    def handle_uma_payreq(callback_uuid: str):
        return sending_vasp.handle_uma_payreq_request(callback_uuid)

    @app.route("/api/sendpayment/<callback_uuid>", methods=["POST"])
    def handle_send_payment(callback_uuid: str):
        return sending_vasp.handle_send_payment(callback_uuid)

    @app.route("/api/uma/pay_invoice", methods=["POST"])
    def handle_pay_uma_invoice():
        return sending_vasp.handle_pay_invoice()

    @app.route("/api/uma/request_pay_invoice", methods=["POST"])
    def handle_request_pay_invoice():
        if not flask_request.json:
            abort_with_error(
                "Request body is required", ErrorCode.MISSING_REQUIRED_UMA_PARAMETERS
            )
        invoice_string = flask_request.json.get("invoice")
        if not invoice_string:
            abort_with_error(
                "Invoice is required.", ErrorCode.MISSING_REQUIRED_UMA_PARAMETERS
            )

        invoice = Invoice.from_bech32_string(invoice_string)
        if not invoice:
            abort_with_error(401, "Invalid invoice.")

        sender_uma = (
            invoice.sender_uma
            if invoice.sender_uma is not None
            else flask_request.json.get("sender")
        )

        if not sender_uma:
            abort_with_error(
                "Sender not provided", ErrorCode.MISSING_REQUIRED_UMA_PARAMETERS
            )

        uma_user_name = sender_uma.split("@")[0]
        if uma_user_name.startswith("$"):
            uma_user_name = uma_user_name[1:]

        return sending_vasp.handle_request_pay_invoice(invoice)

    @app.route("/api/uma/pending_requests")
    def handle_get_pending_requests():
        return sending_vasp.get_pending_uma_requests()
