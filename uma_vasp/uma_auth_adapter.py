from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional

from bolt11 import decode as bolt11_decode
from flask import Flask
from flask import request as flask_request
from lightspark import LightsparkNode
from lightspark import LightsparkSyncClient as LightsparkClient
from lightspark import TransactionStatus
from lightspark.objects.BitcoinNetwork import BitcoinNetwork
from lightspark.objects.IncomingPayment import IncomingPayment
from lightspark.objects.OutgoingPayment import OutgoingPayment
from lightspark.objects.TransactionType import (
    TransactionType as LightsparkTransactionType,
)
from lightspark.utils.currency_amount import amount_as_msats
from uma import ErrorCode
from uma.protocol.currency import Currency
from uma_auth.models.currency import Currency as UmaCurrency
from uma_auth.models.currency_preference import CurrencyPreference
from uma_auth.models.execute_quote_response import ExecuteQuoteResponse
from uma_auth.models.get_balance_response import GetBalanceResponse
from uma_auth.models.get_info_response import GetInfoResponse
from uma_auth.models.list_transactions_response import ListTransactionsResponse
from uma_auth.models.lookup_user_response import LookupUserResponse
from uma_auth.models.make_invoice_request import MakeInvoiceRequest
from uma_auth.models.pay_invoice_request import PayInvoiceRequest
from uma_auth.models.pay_invoice_response import PayInvoiceResponse
from uma_auth.models.pay_to_address_request import PayToAddressRequest
from uma_auth.models.pay_to_address_response import PayToAddressResponse
from uma_auth.models.quote import Quote as UmaQuote
from uma_auth.models.transaction import Transaction as UmaTransaction
from uma_auth.models.transaction_type import TransactionType

from uma_vasp.auth import create_jwt
from uma_vasp.config import Config
from uma_vasp.currencies import CURRENCIES
from uma_vasp.flask_helpers import abort_with_error
from uma_vasp.lightspark_helpers import load_signing_key
from uma_vasp.sending_vasp import SendingVasp
from uma_vasp.user import User
from uma_vasp.user_service import IUserService


@dataclass
class CachedQuote:
    quote: UmaQuote
    user_id: str
    callback_uuid: str


class UmaAuthAdapter:
    def __init__(
        self,
        user_service: IUserService,
        lightspark_client: LightsparkClient,
        sending_vasp: SendingVasp,
        config: Config,
    ) -> None:
        self.user_service = user_service
        self.sending_vasp = sending_vasp
        self.lightspark_client = lightspark_client
        self.config = config
        self.quote_cache: Dict[str, CachedQuote] = {}

    def handle_user_lookup(self, receiver_uma: str):
        lookup_response = self.sending_vasp.handle_uma_lookup(receiver_uma)
        currencies = lookup_response.get("receiverCurrencies") or []
        return LookupUserResponse(
            currencies=[
                CurrencyPreference(
                    currency=UmaCurrency(
                        code=currency.get("code"),
                        symbol=currency.get("symbol"),
                        decimals=currency.get("decimals"),
                        name=currency.get("name"),
                    ),
                    multiplier=currency.get("multiplier"),
                    min=(
                        currency.get("convertible").get("min")
                        if "convertible" in currency
                        else currency.get("minSendable")
                    ),
                    max=(
                        currency.get("convertible").get("max")
                        if "convertible" in currency
                        else currency.get("maxSendable")
                    ),
                )
                for currency in currencies
            ]
        ).to_dict()

    def handle_get_info(self):
        user = self._get_calling_user_or_abort()

        currencies = (
            [
                user_currency_to_uma_auth_currency(CURRENCIES[currency])
                for currency in user.currencies
            ]
            if user.currencies
            else []
        )

        node = self.lightspark_client.get_entity(self.config.node_id, LightsparkNode)
        if not node:
            abort_with_error("Error getting node.", ErrorCode.INTERNAL_ERROR)
        network = "mainnet"
        if node.bitcoin_network == BitcoinNetwork.TESTNET:
            network = "testnet"
        elif node.bitcoin_network == BitcoinNetwork.REGTEST:
            network = "regtest"
        elif node.bitcoin_network == BitcoinNetwork.SIGNET:
            network = "signet"

        return GetInfoResponse(
            alias="Python demo VASP",
            pubkey=node.public_key or "",
            network=network,
            methods=[
                "pay_invoice",
                "make_invoice",
                "lookup_invoice",
                "get_balance",
                "get_budget",
                "get_info",
                "list_transactions",
                "pay_keysend",
                "lookup_user",
                "fetch_quote",
                "execute_quote",
                "pay_to_address",
            ],
            lud16=user.get_uma_address(self.config),
            currencies=currencies,
        ).to_dict()

    def handle_pay_invoice(self, invoice: str, amount: Optional[int]):
        user = self._get_calling_user_or_abort()
        print(f"User {user} is paying invoice {invoice} with amount {amount}.")
        # TODO: pay for this particular user when we have a ledger.
        request_json = flask_request.get_json()
        if not request_json:
            abort_with_error("Request must be JSON", ErrorCode.INVALID_REQUEST_FORMAT)
        try:
            request_data = PayInvoiceRequest.from_dict(request_json)
        except Exception as e:
            abort_with_error(f"Invalid request: {e}", ErrorCode.INVALID_REQUEST_FORMAT)

        invoice = request_data.invoice
        try:
            bolt11 = bolt11_decode(invoice)
        except Exception as e:
            abort_with_error(f"Invalid invoice: {e}", ErrorCode.INVALID_INVOICE)

        amount = request_data.amount
        if not bolt11.amount_msat:
            if not amount:
                abort_with_error(
                    "Need to provide amount for 0 amount invoice.",
                    ErrorCode.INVALID_INPUT,
                )
        elif amount and amount != bolt11.amount_msat:
            abort_with_error(
                "Amount does not match invoice amount.", ErrorCode.INVALID_INPUT
            )

        load_signing_key(self.lightspark_client, self.config)
        payment_result = self.lightspark_client.pay_invoice(
            self.config.node_id,
            invoice,
            timeout_secs=60,
            maximum_fees_msats=1000,
            amount_msats=amount,
        )
        if not payment_result:
            abort_with_error("Payment failed.", ErrorCode.INTERNAL_ERROR)
        payment = self.sending_vasp.wait_for_payment_completion(payment_result)
        if payment.status != TransactionStatus.SUCCESS:
            abort_with_error(
                f"Payment failed. {payment.failure_message}",
                ErrorCode.INTERNAL_ERROR,
            )

        return PayInvoiceResponse(
            preimage=payment_result.payment_preimage or ""
        ).to_dict()

    def handle_create_invoice(self):
        request_json = flask_request.get_json()
        if not request_json:
            abort_with_error(400, "Request must be JSON")
        try:
            request_data = MakeInvoiceRequest.from_dict(request_json)
        except Exception as e:
            abort_with_error(400, f"Invalid request: {e}")

        _ = self._get_calling_user_or_abort()
        # TODO: create invoice for this particular user when we have a ledger.
        invoice = self.lightspark_client.create_invoice(
            self.config.node_id,
            request_data.amount,
            request_data.description,
            expiry_secs=request_data.expiry,
        )
        return UmaTransaction(
            amount=amount_as_msats(invoice.data.amount),
            created_at=round(invoice.created_at.timestamp()),
            description_hash="",  # Not exposed in lightspark api.
            expires_at=round(invoice.data.expires_at.timestamp()),
            invoice=invoice.data.encoded_payment_request,
            description=invoice.data.memo,
            payment_hash=invoice.data.payment_hash,
            type=TransactionType.INCOMING,
        ).to_dict()

    def handle_get_invoice(self, payment_hash: str):
        user = self._get_calling_user_or_abort()
        print(f"User {user} is looking up invoice with payment hash {payment_hash}.")

        # TODO: only allow user to look up their own invoices.

        # It's pretty ugly to have to check both incoming and outgoing payments here, but
        # the Lightspark API doesn't make it easy to get all the information we need in one
        # call.
        invoice = self.lightspark_client.invoice_for_payment_hash(payment_hash)
        payments = self.lightspark_client.outgoing_payments_for_payment_hash(
            payment_hash
        )
        if not invoice and (not payments or len(payments) == 0):
            abort_with_error("Invoice not found.", ErrorCode.REQUEST_NOT_FOUND)
        if not invoice:
            payment_request = payments[0].payment_request_data
            if not payment_request:
                abort_with_error(
                    "No payment_request for this payment.", ErrorCode.REQUEST_NOT_FOUND
                )
            decoded_bolt11 = bolt11_decode(payment_request.encoded_payment_request)
        is_outgoing = payments and len(payments) > 0
        resolved_at = payments[0].resolved_at if is_outgoing else None
        settled_at = None
        if resolved_at:
            settled_at = round(resolved_at.timestamp())
        return UmaTransaction(
            amount=(
                amount_as_msats(invoice.data.amount)
                if invoice
                else (
                    # pylint is being dumb here. It's not possible for decoded_bolt11 to be
                    # used before assignment.
                    int(
                        decoded_bolt11.amount_msat
                    )  # pylint: disable=possibly-used-before-assignment
                    if decoded_bolt11.amount_msat  # pylint: disable=possibly-used-before-assignment
                    else 0
                )
            ),
            created_at=round(
                (
                    invoice.created_at if invoice else decoded_bolt11.date_time
                ).timestamp()
            ),
            expires_at=round(
                (
                    invoice.data.expires_at if invoice else decoded_bolt11.expiry_date
                ).timestamp()
            ),
            settled_at=settled_at,
            payment_hash=payment_hash,
            invoice=(
                invoice.data.encoded_payment_request
                if invoice
                else payment_request.encoded_payment_request
            ),
            type=TransactionType.OUTGOING if is_outgoing else TransactionType.INCOMING,
        ).to_dict()

    def handle_get_balance(self):
        user = self._get_calling_user_or_abort()
        print(f"User {user} is looking up their balance.")
        # TODO: only allow user to look up their own balance based on a ledger.
        node = self.lightspark_client.get_entity(self.config.node_id, LightsparkNode)
        if not node:
            abort_with_error("Error getting node.", ErrorCode.INTERNAL_ERROR)

        if not node.balances:
            abort_with_error("No balances found for node.", ErrorCode.INTERNAL_ERROR)

        return GetBalanceResponse(
            balance=amount_as_msats(node.balances.owned_balance),
            # If you have multiple currencies, you want to include:
            # currency=UmaCurrency(
            #     code=currency_code,
            #     symbol=CURRENCIES[currency_code].symbol,
            #     name=CURRENCIES[currency_code].name,
            #     decimals=CURRENCIES[currency_code].decimals,
            # ),
        ).to_dict()

    def transactions(self):
        user = self._get_calling_user_or_abort()
        print(f"User {user} is looking up their transactions.")
        request_params = flask_request.args
        from_date_sec = request_params.get("from")
        until_date_sec = request_params.get("until")
        limit = request_params.get("limit")
        offset = request_params.get("offset")
        tx_type = request_params.get("type")

        from_date = None
        until_date = None
        if from_date_sec:
            from_date = datetime.fromtimestamp(int(from_date_sec), tz=timezone.utc)
        if until_date_sec:
            until_date = datetime.fromtimestamp(int(until_date_sec), tz=timezone.utc)

        try:
            limit = int(limit) if limit else None
        except ValueError:
            abort_with_error(400, "Invalid limit")
        try:
            offset = int(offset) if offset else None
        except ValueError:
            abort_with_error(400, "Invalid offset")

        if tx_type and tx_type not in ["incoming", "outgoing"]:
            abort_with_error(400, "Invalid type")

        # TODO: only allow user to look up their own transactions based on a ledger.
        node = self.lightspark_client.get_entity(self.config.node_id, LightsparkNode)
        if not node:
            abort_with_error("Error getting node.", ErrorCode.INTERNAL_ERROR)

        ls_types = [
            LightsparkTransactionType.INCOMING_PAYMENT,
            LightsparkTransactionType.OUTGOING_PAYMENT,
        ]
        if tx_type == "incoming":
            ls_types = [LightsparkTransactionType.INCOMING_PAYMENT]
        elif tx_type == "outgoing":
            ls_types = [LightsparkTransactionType.OUTGOING_PAYMENT]

        account = self.lightspark_client.get_current_account()
        ls_transactions = account.get_transactions(
            after_date=from_date,
            before_date=until_date,
            first=limit,
            lightning_node_id=self.config.node_id,
            types=ls_types,
        )

        transactions = []
        for transaction in ls_transactions.entities:
            if isinstance(transaction, OutgoingPayment):
                invoice = transaction.payment_request_data
                expires_at = None
                if invoice:
                    decoded_bolt11 = bolt11_decode(invoice.encoded_payment_request)
                    expires_at = round(decoded_bolt11.expiry_date.timestamp())

                transactions.append(
                    UmaTransaction(
                        amount=amount_as_msats(transaction.amount),
                        created_at=round(transaction.created_at.timestamp()),
                        expires_at=expires_at,
                        settled_at=(
                            round(transaction.resolved_at.timestamp())
                            if transaction.resolved_at
                            else None
                        ),
                        payment_hash=transaction.transaction_hash or "",
                        invoice=(
                            transaction.payment_request_data.encoded_payment_request
                            if transaction.payment_request_data
                            else ""
                        ),
                        type=TransactionType.OUTGOING,
                    ).to_dict()
                )
            elif isinstance(transaction, IncomingPayment):
                transactions.append(
                    UmaTransaction(
                        amount=amount_as_msats(transaction.amount),
                        created_at=round(transaction.created_at.timestamp()),
                        # TODO: Get the expiry date from the invoice. It's super innefficient to
                        # have to look up the invoice for each transaction.
                        expires_at=None,
                        settled_at=(
                            round(transaction.resolved_at.timestamp())
                            if transaction.resolved_at
                            else None
                        ),
                        payment_hash=transaction.transaction_hash or "",
                        # TODO: Get the invoice from the transaction.
                        invoice="",
                        type=TransactionType.INCOMING,
                    ).to_dict()
                )
        return ListTransactionsResponse(transactions=transactions).to_dict()

    def handle_get_quote(self):
        user = self._get_calling_user_or_abort()
        receiving_uma = flask_request.args.get("receiver_address")
        sending_currency_code = flask_request.args.get("sending_currency_code")
        receiving_currency_code = flask_request.args.get("receiving_currency_code")
        locked_currency_amount = flask_request.args.get("locked_currency_amount")
        locked_currency_side = (
            flask_request.args.get("locked_currency_side") or "sending"
        )
        is_sender_locked = locked_currency_side.lower() == "sending"
        if (
            not receiving_uma
            or not sending_currency_code
            or not receiving_currency_code
            or not locked_currency_amount
        ):
            abort_with_error(
                "Missing required parameters", ErrorCode.MISSING_REQUIRED_UMA_PARAMETERS
            )
        if not locked_currency_amount.isnumeric():
            abort_with_error("Invalid locked currency amount", ErrorCode.INVALID_INPUT)
        if not is_sender_locked and locked_currency_side.lower() != "receiving":
            abort_with_error(400, "Invalid locked currency side")
        uma_lookup_result = self.sending_vasp.handle_uma_lookup(receiving_uma)
        receiving_currencies = uma_lookup_result.get("receiverCurrencies")
        if not receiving_currencies:
            abort_with_error(400, "Receiver not found")

        receiving_currency = next(
            (
                currency
                for currency in receiving_currencies
                if currency.get("code") == receiving_currency_code
            ),
            None,
        )

        if not receiving_currency:
            abort_with_error(
                "Receiver does not accept the specified currency",
                ErrorCode.INVALID_CURRENCY,
            )

        if (
            is_sender_locked
            and sending_currency_code != "BTC"
            and sending_currency_code != "SAT"
        ):
            abort_with_error(
                "Sending currencies besides BTC are not yet supported",
                ErrorCode.INVALID_CURRENCY,
            )

        uma_payreq_result = self.sending_vasp.handle_uma_payreq(
            uma_lookup_result["callbackUuid"],
            is_amount_in_msats=is_sender_locked,
            amount=(
                int(locked_currency_amount) * 1000
                if is_sender_locked
                else int(locked_currency_amount)
            ),
            receiving_currency_code=receiving_currency_code,
            user=user,
        )

        quote = UmaQuote(
            payment_hash=uma_payreq_result.payment_hash,
            expires_at=uma_payreq_result.invoice_expires_at,
            multiplier=uma_payreq_result.conversion_rate / 1000,
            sending_currency=UmaCurrency(
                code="SAT",
                symbol=CURRENCIES["SAT"].symbol,
                name=CURRENCIES["SAT"].name,
                decimals=CURRENCIES["SAT"].decimals,
            ),
            receiving_currency=UmaCurrency(
                code=receiving_currency.get("code"),
                symbol=receiving_currency.get("symbol"),
                name=receiving_currency.get("name"),
                decimals=receiving_currency.get("decimals"),
            ),
            fees=round(uma_payreq_result.exchange_fees_msats / 1000),
            total_sending_amount=round(uma_payreq_result.amount_msats / 1000),
            total_receiving_amount=uma_payreq_result.amount_receiving_currency,
            created_at=round(datetime.now().timestamp()),
        )

        self.quote_cache[quote.payment_hash] = CachedQuote(
            quote=quote, user_id=user.id, callback_uuid=uma_payreq_result.callback_uuid
        )

        return quote.to_dict()

    def handle_execute_quote(self, payment_hash: str):
        user = self._get_calling_user_or_abort()
        quote = self.quote_cache.get(payment_hash)
        if not quote:
            abort_with_error("Quote not found", ErrorCode.QUOTE_NOT_FOUND)
        if quote.user_id != user.id:
            abort_with_error("Quote does not belong to user", ErrorCode.FORBIDDEN)
        if quote.quote.expires_at < datetime.now().timestamp():
            abort_with_error("Quote expired", ErrorCode.QUOTE_EXPIRED)

        payment = self.sending_vasp.handle_send_payment(quote.callback_uuid)
        preimage = payment.get("preimage")
        if not preimage:
            abort_with_error(
                "Payment succeeded, but missing preimage", ErrorCode.INTERNAL_ERROR
            )

        self.quote_cache.pop(payment_hash)

        return ExecuteQuoteResponse(preimage=preimage).to_dict()

    def handle_pay_to_address(self):
        user = self._get_calling_user_or_abort()
        request_json = flask_request.get_json()
        if not request_json:
            abort_with_error(400, "Request must be JSON")

        try:
            request_data = PayToAddressRequest.from_dict(request_json)
        except Exception as e:
            abort_with_error(400, f"Invalid request: {e}")

        if request_data.sending_currency_code in ("BTC", "SAT"):
            abort_with_error(
                "Sending currencies besides BTC/SAT are not yet supported",
                ErrorCode.INVALID_CURRENCY,
            )

        amount = request_data.sending_currency_amount

        uma_lookup_result = self.sending_vasp.handle_uma_lookup(
            request_data.receiver_address
        )
        receiving_currencies = uma_lookup_result.get("receiverCurrencies", [])
        default_currency = (
            receiving_currencies[0].get("code")
            if len(receiving_currencies) > 0
            else "SAT"
        )
        receiving_currency_code = (
            request_data.receiving_currency_code or default_currency
        )
        receiving_currency = next(
            (
                currency
                for currency in receiving_currencies
                if currency.get("code") == receiving_currency_code
            ),
            None,
        )
        if len(receiving_currencies) > 0 and not receiving_currency:
            abort_with_error(
                "Receiver does not accept the specified currency",
                ErrorCode.INVALID_CURRENCY,
            )

        if not receiving_currency:
            receiving_currency = CURRENCIES[receiving_currency_code].to_dict()

        uma_payreq_result = self.sending_vasp.handle_uma_payreq(
            uma_lookup_result["callbackUuid"],
            is_amount_in_msats=True,
            amount=int(amount) * 1000,
            receiving_currency_code=receiving_currency_code,
            user=user,
        )

        payment = self.sending_vasp.handle_send_payment(uma_payreq_result.callback_uuid)

        quote = UmaQuote(
            payment_hash=uma_payreq_result.payment_hash,
            expires_at=uma_payreq_result.invoice_expires_at,
            multiplier=uma_payreq_result.conversion_rate,
            sending_currency=UmaCurrency(
                code="SAT",
                symbol=CURRENCIES["SAT"].symbol,
                name=CURRENCIES["SAT"].name,
                decimals=CURRENCIES["SAT"].decimals,
            ),
            receiving_currency=UmaCurrency(
                code=receiving_currency["code"],
                symbol=receiving_currency["symbol"],
                name=receiving_currency["name"],
                decimals=receiving_currency["decimals"],
            ),
            fees=round(uma_payreq_result.exchange_fees_msats / 1000),
            total_sending_amount=round(uma_payreq_result.amount_msats / 1000),
            total_receiving_amount=uma_payreq_result.amount_receiving_currency,
            created_at=round(datetime.now(tz=timezone.utc).timestamp()),
        )

        preimage = payment.get("preimage")
        if not preimage:
            abort_with_error(
                "Payment succeeded, but missing preimage", ErrorCode.INTERNAL_ERROR
            )

        return PayToAddressResponse(preimage=preimage, quote=quote).to_dict()

    def handle_nwc_token_exchange(self):
        user = self._get_calling_user_or_abort()
        body = flask_request.get_json()
        requested_expiration = body.get("expiration")
        user_nwc_jwt = create_jwt(user, self.config, requested_expiration)
        return {"token": user_nwc_jwt}

    def _get_calling_user_or_abort(self) -> User:
        user = self.user_service.get_calling_user_from_request(
            flask_request.url, dict(flask_request.headers)
        )
        if not user:
            abort_with_error("Unauthorized", ErrorCode.USER_NOT_FOUND)
        return user


def register_routes(app: Flask, uma_auth_adapter: UmaAuthAdapter):
    @app.route("/umanwc/balance")
    def balance():
        return uma_auth_adapter.handle_get_balance()

    @app.route("/umanwc/payments", methods=["GET"])
    def transactions():
        return uma_auth_adapter.transactions()

    @app.route("/umanwc/payments/bolt11", methods=["POST"])
    def handle_pay_invoice():
        request_data = flask_request.get_json()
        if not request_data:
            abort_with_error("Request must be JSON", ErrorCode.INVALID_REQUEST_FORMAT)
        if "invoice" not in request_data:
            abort_with_error(
                "No invoice in request", ErrorCode.MISSING_REQUIRED_UMA_PARAMETERS
            )
        return uma_auth_adapter.handle_pay_invoice(
            request_data["invoice"], request_data.get("amount")
        )

    @app.route("/umanwc/invoice", methods=["POST"])
    def handle_create_invoice():
        return uma_auth_adapter.handle_create_invoice()

    @app.route("/umanwc/invoices/<payment_hash>")
    def handle_get_invoice(payment_hash: str):
        return uma_auth_adapter.handle_get_invoice(payment_hash)

    @app.route("/umanwc/receiver/<receiver_type>/<receiver_uma>")
    def handle_lookup_user(receiver_type: str, receiver_uma: str):
        if receiver_type != "lud16":
            abort_with_error(
                "Only UMA receivers are supported",
                ErrorCode.MISSING_REQUIRED_UMA_PARAMETERS,
            )
        return uma_auth_adapter.handle_user_lookup(receiver_uma)

    @app.route("/umanwc/quote/lud16")
    def handle_get_quote():
        return uma_auth_adapter.handle_get_quote()

    @app.route("/umanwc/quote/<payment_hash>", methods=["POST"])
    def handle_execute_quote(payment_hash: str):
        return uma_auth_adapter.handle_execute_quote(payment_hash)

    @app.route("/umanwc/payments/lud16", methods=["POST"])
    def handle_pay_address():
        return uma_auth_adapter.handle_pay_to_address()

    @app.route("/umanwc/payments/keysend", methods=["POST"])
    def handle_pay_keysend():
        # TODO: Implement keysend payments.
        return abort_with_error("Keysend Not implemented", ErrorCode.NOT_IMPLEMENTED)

    @app.route("/umanwc/info")
    def handle_info():
        return uma_auth_adapter.handle_get_info()

    @app.route("/umanwc/token", methods=["POST"])
    def handle_nwc_token_exchange():
        return uma_auth_adapter.handle_nwc_token_exchange()


def user_currency_to_uma_auth_currency(user_currency: Currency) -> CurrencyPreference:
    return CurrencyPreference(
        min=user_currency.min_sendable,
        max=user_currency.max_sendable,
        multiplier=user_currency.millisatoshi_per_unit,
        currency=UmaCurrency(
            code=user_currency.code,
            symbol=user_currency.symbol,
            decimals=user_currency.decimals,
            name=user_currency.name,
        ),
    )
