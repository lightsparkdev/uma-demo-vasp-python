import json

from flask import abort
from flask import request as flask_request
from lightspark import LightsparkSyncClient as LightsparkClient
from uma import (
    IPublicKeyCache,
    IUmaInvoiceCreator,
    KycStatus,
    LnurlpRequest,
    PayerDataOptions,
    PayRequest,
    create_lnurlp_response,
    create_pay_req_response,
    fetch_public_key_for_vasp,
    is_uma_lnurlp_query,
    parse_lnurlp_request,
    parse_pay_request,
    verify_pay_request_signature,
    verify_uma_lnurlp_query_signature,
)
from uma_vasp.address_helpers import get_domain_from_uma_address

from uma_vasp.app import app
from uma_vasp.config import Config
from uma_vasp.currencies import (
    CURRENCIES,
    DECIMALS_PER_UNIT,
    MSATS_PER_UNIT,
    RECEIVER_FEES_MSATS,
)
from uma_vasp.lightspark_helpers import get_node
from uma_vasp.user import User
from uma_vasp.user_service import IUserService

PAY_REQUEST_CALLBACK = "/api/uma/payreq/"


class ReceivingVasp:
    def __init__(
        self,
        user_service: IUserService,
        lightspark_client: LightsparkClient,
        pubkey_cache: IPublicKeyCache,
        config: Config,
    ) -> None:
        self.user_service = user_service
        self.vasp_pubkey_cache = pubkey_cache
        self.lightspark_client = lightspark_client
        self.config = config

    def handle_lnurlp_request(self, username: str):
        if not is_uma_lnurlp_query(flask_request.url):
            # TODO: Fallback to raw lnurl.
            print("Not a UMA LNURLP query")

        print(f"Handling UMA LNURLP query for user {username}")
        lnurlp_request: LnurlpRequest
        try:
            lnurlp_request = parse_lnurlp_request(flask_request.url)
        except Exception as e:
            print(f"Invalid UMA lnurlp request: {e}")
            abort(
                400,
                {
                    "status": "ERROR",
                    "reason": f"Invalid UMA lnurlp request: {e}",
                },
            )

        sender_vasp_signing_pubkey: bytes
        try:
            sender_vasp_signing_pubkey = fetch_public_key_for_vasp(
                lnurlp_request.vasp_domain, self.vasp_pubkey_cache
            ).signing_pubkey
        except Exception as e:
            abort(
                424,
                {
                    "status": "ERROR",
                    "reason": f"Cannot fetch public key for vasp {lnurlp_request.vasp_domain}: {e}",
                },
            )

        user = self.user_service.get_user_from_uma_user_name(username)
        if not user:
            abort(
                404,
                {
                    "status": "ERROR",
                    "reason": f"Cannot find user {lnurlp_request.receiver_address}",
                },
            )

        try:
            verify_uma_lnurlp_query_signature(
                request=lnurlp_request,
                other_vasp_signing_pubkey=sender_vasp_signing_pubkey,
            )
        except Exception as e:
            abort(
                400,
                {
                    "status": "ERROR",
                    "reason": f"Invalid signature: {e}",
                },
            )

        metadata = self._create_metadata(user)
        payer_data_options = PayerDataOptions(
            name_required=False,
            email_required=False,
            compliance_required=True,
        )
        callback = self.config.get_complete_url(PAY_REQUEST_CALLBACK + user.id)

        response = create_lnurlp_response(
            request=lnurlp_request,
            signing_private_key=self.config.get_signing_privkey(),
            requires_travel_rule_info=True,
            callback=callback,
            encoded_metadata=metadata,
            min_sendable_sats=1,
            max_sendable_sats=10_000_000,
            payer_data_options=payer_data_options,
            currency_options=[CURRENCIES[currency] for currency in user.currencies],
            receiver_kyc_status=KycStatus.VERIFIED,
        )

        return response.to_dict()

    def handle_pay_request_callback(self, user_id: str):
        user = self.user_service.get_user_from_id(user_id)
        if not user:
            abort(
                404,
                {
                    "status": "ERROR",
                    "reason": f"Cannot find user {user_id}",
                },
            )

        request: PayRequest
        try:
            request = parse_pay_request(flask_request.get_data(as_text=True))
        except Exception as e:
            print(f"Invalid UMA pay request: {e}")
            abort(
                400,
                {
                    "status": "ERROR",
                    "reason": f"Invalid UMA pay request: {e}",
                },
            )

        if not request.payer_data.compliance:
            abort(
                400,
                {
                    "status": "ERROR",
                    "reason": "Compliance data is required.",
                },
            )

        vasp_domain = get_domain_from_uma_address(request.payer_data.identifier)
        sender_vasp_signing_pubkey = fetch_public_key_for_vasp(
            vasp_domain=vasp_domain,
            cache=self.vasp_pubkey_cache,
        ).signing_pubkey
        verify_pay_request_signature(
            request=request,
            other_vasp_signing_pubkey=sender_vasp_signing_pubkey,
        )

        metadata = (
            self._create_metadata(user) + "{" + request.payer_data.to_json() + "}"
        )

        msats_per_currency_unit = MSATS_PER_UNIT.get(request.currency_code, None)
        if msats_per_currency_unit is None:
            abort(
                400,
                {
                    "status": "ERROR",
                    "reason": f"Currency code {request.currency_code} in the pay request is not supported. We support only {','.join(str(currency_code) for currency_code in MSATS_PER_UNIT.keys())}.",
                },
            )
        receiver_fees_msats = RECEIVER_FEES_MSATS[request.currency_code]
        node = get_node(self.lightspark_client, self.config.node_id)

        return create_pay_req_response(
            request=request,
            invoice_creator=LightsparkInvoiceCreator(
                self.lightspark_client, self.config
            ),
            metadata=metadata,
            currency_code=request.currency_code,
            currency_decimals=DECIMALS_PER_UNIT[request.currency_code],
            msats_per_currency_unit=msats_per_currency_unit,
            receiver_fees_msats=receiver_fees_msats,
            receiver_node_pubkey=node.public_key,
            receiver_utxos=node.uma_prescreening_utxos,
            utxo_callback=self.config.get_complete_url("/api/uma/utxoCallback?txid=12345"),
        ).to_dict()

    def _create_metadata(self, user: User) -> str:
        metadata = [
            ["text/plain", f"Pay to {self.config.get_uma_domain()} user {user.name}"],
            ["text/identifier", user.get_uma_address(self.config)],
        ]
        return json.dumps(metadata)


class LightsparkInvoiceCreator(IUmaInvoiceCreator):
    def __init__(self, client: LightsparkClient, config: Config) -> None:
        super().__init__()
        self.client = client
        self.config = config

    def create_uma_invoice(
        self,
        amount_msats: int,
        metadata: str,
    ) -> str:
        return self.client.create_uma_invoice(
            node_id=self.config.node_id,
            amount_msats=amount_msats,
            metadata=metadata,
            expiry_secs=300,
        ).data.encoded_payment_request


def register_routes(receiving_vasp: ReceivingVasp):
    @app.route("/.well-known/lnurlp/<username>")
    def handle_lnurlp_request(username: str):
        return receiving_vasp.handle_lnurlp_request(username)

    @app.route(PAY_REQUEST_CALLBACK + "<user_id>", methods=["POST"])
    def handle_pay_request_callback(user_id: str):
        return receiving_vasp.handle_pay_request_callback(user_id)
