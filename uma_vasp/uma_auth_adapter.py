from typing import NoReturn, Optional

from flask import Flask, request as flask_request
from lightspark.utils.currency_amount import amount_as_msats
from lightspark import (
    LightsparkSyncClient as LightsparkClient,
    TransactionStatus,
    LightsparkNode,
)

from uma_vasp.config import Config
from uma_vasp.flask_helpers import abort_with_error
from uma_vasp.lightspark_helpers import load_signing_key
from uma_vasp.sending_vasp import SendingVasp
from uma_vasp.user import User
from uma_vasp.user_service import IUserService


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

    def handle_user_lookup(self, receiver_uma: str):
        return self.sending_vasp.handle_uma_lookup(receiver_uma)

    def handle_pay_invoice(self, invoice: str, amount: Optional[int]):
        user = self.sending_vasp._get_calling_user_or_abort()
        print(f"User {user} is paying invoice {invoice} with amount {amount}.")
        # TODO: pay for this particular user when we have a ledger.
        load_signing_key(self.lightspark_client, self.config)
        payment_result = self.lightspark_client.pay_invoice(
            self.config.node_id,
            invoice,
            timeout_secs=60,
            maximum_fees_msats=1000,
            amount_msats=amount,
        )
        if not payment_result:
            abort_with_error(500, "Payment failed.", "PAYMENT_FAILED")
        payment = self.sending_vasp.wait_for_payment_completion(payment_result)
        if payment.status != TransactionStatus.SUCCESS:
            abort_with_error(
                500, f"Payment failed. {payment.failure_message}", "PAYMENT_FAILED"
            )
        return {"preimage": payment.payment_preimage}

    def handle_create_invoice(
        self, amount: int, description: str, description_hash: str, expiry: int
    ):
        user = self.sending_vasp._get_calling_user_or_abort()
        # TODO: create invoice for this particular user when we have a ledger.
        print(f"User {user} is creating invoice with amount {amount}.")
        # TODO: Add ability to pass in description_hash directly.
        invoice = self.lightspark_client.create_invoice(
            self.config.node_id, amount, description, expiry_secs=expiry
        )
        return {
            "amount": amount_as_msats(invoice.data.amount),
            "created_at": round(invoice.created_at.timestamp()),
            "description_hash": "",  # TODO
            "expires_at": round(invoice.data.expires_at.timestamp()),
            "expiry": 0,  # TODO
            "memo": invoice.data.memo,
            "metadata": "",  # TODO
            "payment_hash": invoice.data.payment_hash,
            "payment_request": invoice.data.encoded_payment_request,
            "preimage": "",  # TODO
            "settled": False,
            "type": "incoming",
        }

    def handle_get_invoice(self, payment_hash: str):
        user = self.sending_vasp._get_calling_user_or_abort()
        print(f"User {user} is looking up invoice with payment hash {payment_hash}.")
        # TODO: only allow user to look up their own invoices.

        # TODO: Add the payment_hash lookup function to the lightspark client.
        return {}

    def handle_get_balance(self):
        user = self.sending_vasp._get_calling_user_or_abort()
        print(f"User {user} is looking up their balance.")
        # TODO: only allow user to look up their own balance based on a ledger.
        node = self.lightspark_client.get_entity(self.config.node_id, LightsparkNode)
        if not node:
            abort_with_error(500, "Error getting node.")

        if not node.balances:
            abort_with_error(500, "No balances found for node.")
        return {
            "balances": [
                {
                    "currency": "BTC",
                    "balance": round(amount_as_msats(node.balances.owned_balance) / 1000),
                    "decimals": 8,
                    "symbol": "BTC",
                }
            ]
        }

    def _get_calling_user_or_abort(self) -> User:
        user = self.user_service.get_calling_user_from_request(
            flask_request.url, flask_request.headers
        )
        if not user:
            abort_with_error(401, "Unauthorized")
        return user


def register_routes(app: Flask, uma_auth_adapter: UmaAuthAdapter):
    @app.route("/umanwc/payments/bolt11", methods=["POST"])
    def handle_pay_invoice():
        request_data = flask_request.get_json()
        if not request_data:
            abort_with_error(400, "Request must be JSON")
        if "invoice" not in request_data:
            abort_with_error(400, "No invoice in request")
        return uma_auth_adapter.handle_pay_invoice(
            request_data["invoice"], request_data.get("amount")
        )

    @app.route("/umanwc/invoice", methods=["POST"])
    def handle_create_invoice():
        request_data = flask_request.get_json()
        if not request_data:
            abort_with_error(400, "Request must be JSON")
        if "amount" not in request_data:
            abort_with_error(400, "No amount in request")
        if not isinstance(request_data["amount"], int):
            abort_with_error(400, "Amount must be an integer")
        if request_data["amount"] < 0:
            abort_with_error(400, "Amount must be positive or zero")
        return uma_auth_adapter.handle_create_invoice(
            request_data["amount"],
            request_data.get("description"),
            request_data.get("description_hash"),
            request_data.get("expiry"),
        )

    @app.route("/umanwc/invoices/<payment_hash>")
    def handle_get_invoice(payment_hash: str):
        return uma_auth_adapter.handle_get_invoice(payment_hash)

    @app.route("/umanwc/balance")
    def handle_get_balance():
        return uma_auth_adapter.handle_get_balance()

    @app.route("/umanwc/payments")
    def handle_list_payments():
        # TODO: implement this.
        return uma_auth_adapter.handle_get_balance()

    @app.route("/umanwc/receiver_info/<receiver_uma>")
    def handle_lookup_user(receiver_uma: str):
        return uma_auth_adapter.sending_vasp.handle_uma_lookup(receiver_uma)

    @app.route("/umanwc/quote")
    def handle_get_quote():
        # TODO: implement this.
        return uma_auth_adapter.handle_get_balance()

    @app.route("/umanwc/quote/<payment_hash>", methods=["POST"])
    def handle_execute_quote(payment_hash: str):
        # TODO: implement this.
        return uma_auth_adapter.handle_get_balance()

    @app.route("/umanwc/payments/lnurl", methods=["POST"])
    def handle_pay_address():
        # TODO: implement this.
        return uma_auth_adapter.handle_get_balance()
