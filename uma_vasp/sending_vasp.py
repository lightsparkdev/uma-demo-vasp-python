import requests
from flask import abort
from flask import request as flask_request
from lightspark import LightsparkSyncClient as LightsparkClient
from uma import (
    InvalidSignatureException,
    IPublicKeyCache,
    LnurlpResponse,
    create_lnurlp_request_url,
    fetch_public_key_for_vasp,
    parse_lnurlp_response,
    verify_uma_lnurlp_response_signature,
)

from uma_vasp.app import app
from uma_vasp.config import Config
from uma_vasp.currencies import CURRENCIES
from uma_vasp.sending_vasp_request_cache import ISendingVaspRequestCache
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
        user = self.user_service.get_calling_user_from_request(
            flask_request.url, flask_request.headers
        )
        if not user:
            abort(401)

        url = create_lnurlp_request_url(
            signing_private_key=self.config.get_signing_privkey(),
            receiver_address=receiver_uma,
            sender_vasp_domain=self.config.get_uma_domain(),
            is_subject_to_travel_rule=True,
        )

        response = requests.get(url)
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
            vasp_domain=self._get_domain_from_uma_address(receiver_uma),
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
        return "OK"

    def handle_send_payment(self, callback_uuid: str):
        return "OK"

    def _get_domain_from_uma_address(self, uma_address: str) -> str:
        try:
            [_, domain] = uma_address.split("@")
            return domain
        except ValueError as ex:
            abort(
                400,
                {
                    "status": "ERROR",
                    "reason": f"Invalid UMA address: {ex}",
                },
            )


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
