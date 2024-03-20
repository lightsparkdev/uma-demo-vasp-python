import json

from flask import Flask, current_app
from flask import request as flask_request
from lightspark import LightsparkSyncClient as LightsparkClient
from uma import (
    INonceCache,
    IPublicKeyCache,
    IUmaInvoiceCreator,
    KycStatus,
    LnurlpRequest,
    LnurlpResponse,
    PayReqResponse,
    PayRequest,
    PubkeyResponse,
    compliance_from_payer_data,
    create_counterparty_data_options,
    create_pay_req_response,
    create_uma_lnurlp_response,
    fetch_public_key_for_vasp,
    none_throws,
    parse_lnurlp_request,
    parse_pay_request,
    verify_pay_request_signature,
    verify_uma_lnurlp_query_signature,
)

from uma_vasp.address_helpers import get_domain_from_uma_address
from uma_vasp.compliance_service import IComplianceService
from uma_vasp.config import Config
from uma_vasp.currencies import (
    CURRENCIES,
    DECIMALS_PER_UNIT,
    MSATS_PER_UNIT,
    RECEIVER_FEES_MSATS,
)
from uma_vasp.lightspark_helpers import get_node
from uma_vasp.uma_exception import UmaException
from uma_vasp.user import User
from uma_vasp.user_service import IUserService

PAY_REQUEST_CALLBACK = "/api/uma/payreq/"


class ReceivingVasp:
    def __init__(
        self,
        user_service: IUserService,
        compliance_service: IComplianceService,
        lightspark_client: LightsparkClient,
        pubkey_cache: IPublicKeyCache,
        config: Config,
        nonce_cache: INonceCache,
    ) -> None:
        self.user_service = user_service
        self.compliance_service = compliance_service
        self.vasp_pubkey_cache = pubkey_cache
        self.lightspark_client = lightspark_client
        self.config = config
        self.nonce_cache = nonce_cache

    def handle_lnurlp_request(self, username: str):
        print(f"Handling LNURLP query for user {username}")
        lnurlp_request: LnurlpRequest
        try:
            lnurlp_request = parse_lnurlp_request(flask_request.url)
        except Exception as e:
            print(f"Invalid UMA lnurlp request: {e}")
            raise UmaException(
                f"Invalid UMA lnurlp request: {e}",
                status_code=400,
            )

        user = self.user_service.get_user_from_uma_user_name(username)
        if not user:
            raise UmaException(
                f"Cannot find user {lnurlp_request.receiver_address}",
                status_code=404,
            )

        if not lnurlp_request.is_uma_request():
            return self._handle_non_uma_lnurlp_request(user).to_dict()

        if not self.compliance_service.should_accept_transaction_from_vasp(
            none_throws(lnurlp_request.vasp_domain), lnurlp_request.receiver_address
        ):
            raise UmaException(
                f"Cannot accept transactions from vasp {lnurlp_request.vasp_domain}",
                status_code=403,
            )

        sender_vasp_pubkey_response: PubkeyResponse
        try:
            sender_vasp_pubkey_response = fetch_public_key_for_vasp(
                none_throws(lnurlp_request.vasp_domain), self.vasp_pubkey_cache
            )
        except Exception as e:
            raise UmaException(
                f"Cannot fetch public key for vasp {lnurlp_request.vasp_domain}: {e}",
                status_code=424,
            )

        # Skip signature verification in testing mode to avoid needing to run 2 VASPs.
        is_testing = current_app.config.get("TESTING", False)
        if not is_testing:
            try:
                verify_uma_lnurlp_query_signature(
                    request=lnurlp_request,
                    other_vasp_pubkeys=sender_vasp_pubkey_response,
                    nonce_cache=self.nonce_cache,
                )
            except Exception as e:
                raise UmaException(
                    f"Invalid signature: {e}",
                    status_code=400,
                )

        metadata = self._create_metadata(user)
        payer_data_options = create_counterparty_data_options(
            {
                "name": False,
                "email": False,
                "identifier": True,
                "compliance": True,
            }
        )
        callback = self.config.get_complete_url(PAY_REQUEST_CALLBACK + user.id)

        response = create_uma_lnurlp_response(
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

    def _handle_non_uma_lnurlp_request(self, receiver_user: User) -> LnurlpResponse:
        metadata = self._create_metadata(receiver_user)
        return LnurlpResponse(
            tag="payRequest",
            callback=self.config.get_complete_url(
                PAY_REQUEST_CALLBACK + receiver_user.id
            ),
            min_sendable=1_000,
            max_sendable=10_000_000_000,
            encoded_metadata=metadata,
            currencies=[CURRENCIES[currency] for currency in receiver_user.currencies],
            required_payer_data=None,
            compliance=None,
            uma_version=None,
        )

    def handle_pay_request_callback(self, user_id: str):
        user = self.user_service.get_user_from_id(user_id)
        if not user:
            raise UmaException(
                f"Cannot find user {user_id}",
                status_code=404,
            )

        request: PayRequest
        try:
            request_data = (
                flask_request.get_data(as_text=True)
                if flask_request.method == "POST"
                else json.dumps(flask_request.args)
            )
            request = parse_pay_request(request_data)
        except Exception as e:
            print(f"Invalid UMA pay request: {e}")
            raise UmaException(
                f"Invalid UMA pay request: {e}",
                status_code=400,
            )
        if not request.is_uma_request():
            return self._handle_non_uma_pay_request(request, user).to_dict()

        payer_data = none_throws(request.payer_data)
        vasp_domain = get_domain_from_uma_address(payer_data.get("identifier", ""))
        if not self.compliance_service.should_accept_transaction_from_vasp(
            vasp_domain, user.get_uma_address(self.config)
        ):
            raise UmaException(
                f"Cannot accept transactions from vasp {vasp_domain}",
                status_code=403,
            )

        # Skip signature verification in testing mode to avoid needing to run 2 VASPs.
        is_testing = current_app.config.get("TESTING", False)
        if not is_testing:
            sender_vasp_pubkeys = fetch_public_key_for_vasp(
                vasp_domain=vasp_domain,
                cache=self.vasp_pubkey_cache,
            )
            verify_pay_request_signature(
                request=request,
                other_vasp_pubkeys=sender_vasp_pubkeys,
                nonce_cache=self.nonce_cache,
            )

        metadata = self._create_metadata(user) + json.dumps(payer_data)

        receiving_currency_code = none_throws(request.receiving_currency_code)
        msats_per_currency_unit = MSATS_PER_UNIT.get(receiving_currency_code, None)
        if msats_per_currency_unit is None:
            raise UmaException(
                f"Currency code {receiving_currency_code} in the pay request is not supported. We support only {','.join(str(currency_code) for currency_code in MSATS_PER_UNIT.keys())}.",
                status_code=400,
            )
        receiver_fees_msats = RECEIVER_FEES_MSATS[receiving_currency_code]

        receiver_uma = user.get_uma_address(self.config)
        compliance_data = compliance_from_payer_data(payer_data)
        if compliance_data:
            self.compliance_service.pre_screen_transaction(
                sending_uma_address=payer_data.get("identifier", ""),
                receiving_uma_address=receiver_uma,
                amount_msats=(
                    request.amount
                    if request.sending_amount_currency_code is None
                    else round(request.amount * msats_per_currency_unit)
                    + receiver_fees_msats
                ),
                counterparty_node_id=compliance_data.node_pubkey,
                counterparty_utxos=compliance_data.utxos,
            )

        node = get_node(self.lightspark_client, self.config.node_id)

        return create_pay_req_response(
            request=request,
            invoice_creator=LightsparkInvoiceCreator(
                self.lightspark_client, self.config
            ),
            metadata=metadata,
            receiving_currency_code=receiving_currency_code,
            receiving_currency_decimals=DECIMALS_PER_UNIT[receiving_currency_code],
            msats_per_currency_unit=msats_per_currency_unit,
            receiver_fees_msats=receiver_fees_msats,
            receiver_node_pubkey=node.public_key,
            receiver_utxos=node.uma_prescreening_utxos,
            utxo_callback=self.config.get_complete_url(
                "/api/uma/utxoCallback?txid=12345"
            ),
            payee_identifier=receiver_uma,
            signing_private_key=self.config.get_signing_privkey(),
            payee_data=None,
        ).to_dict()

    def _handle_non_uma_pay_request(
        self, request: PayRequest, receiver_user: User
    ) -> PayReqResponse:
        metadata = self._create_metadata(receiver_user)
        if request.payer_data is not None:
            metadata += json.dumps(request.payer_data)
        return create_pay_req_response(
            request=request,
            invoice_creator=LightsparkInvoiceCreator(
                self.lightspark_client, self.config
            ),
            metadata=metadata,
            receiving_currency_code=request.receiving_currency_code,
            receiving_currency_decimals=(
                DECIMALS_PER_UNIT[request.receiving_currency_code]
                if request.receiving_currency_code is not None
                else None
            ),
            msats_per_currency_unit=(
                MSATS_PER_UNIT.get(request.receiving_currency_code, None)
                if request.receiving_currency_code is not None
                else None
            ),
            receiver_fees_msats=(
                RECEIVER_FEES_MSATS.get(request.receiving_currency_code, None)
                if request.receiving_currency_code is not None
                else None
            ),
            receiver_node_pubkey=None,
            receiver_utxos=[],
            utxo_callback=None,
            payee_identifier=None,
            signing_private_key=None,
            payee_data=None,
        )

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


def register_routes(app: Flask, receiving_vasp: ReceivingVasp):
    @app.route("/.well-known/lnurlp/<username>")
    def handle_lnurlp_request(username: str):
        return receiving_vasp.handle_lnurlp_request(username)

    @app.route(PAY_REQUEST_CALLBACK + "<user_id>", methods=["POST"])
    def handle_uma_pay_request_callback(user_id: str):
        return receiving_vasp.handle_pay_request_callback(user_id)

    @app.route(PAY_REQUEST_CALLBACK + "<user_id>", methods=["GET"])
    def handle_lnurl_pay_request_callback(user_id: str):
        return receiving_vasp.handle_pay_request_callback(user_id)
