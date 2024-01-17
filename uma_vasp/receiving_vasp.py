import json
from flask import abort, request
from uma_vasp.app import app
from uma import (
    parse_lnurlp_request,
    fetch_public_key_for_vasp,
    verify_uma_lnurlp_query_signature,
    InMemoryPublicKeyCache,
    PayerDataOptions,
    KycStatus,
    create_lnurlp_response,
    is_uma_lnurlp_query,
)

from uma_vasp.config import Config
from uma_vasp.currencies import CURRENCIES
from uma_vasp.user import User
from uma_vasp.user_service import IUserService

PAY_REQUEST_CALLBACK = "/api/uma/payreq/"


class ReceivingVasp:
    def __init__(
        self,
        user_service: IUserService,
        config: Config,
    ) -> None:
        self.user_service = user_service
        self.vasp_pubkey_cache = InMemoryPublicKeyCache()
        self.config = config

    def handle_lnurlp_request(self, username: str):
        if not is_uma_lnurlp_query(request.url):
            # TODO: Fallback to raw lnurl.
            print("Not a UMA LNURLP query")

        print(f"Handling UMA LNURLP query for user {username}")
        try:
            lnurlp_request = parse_lnurlp_request(request.url)
        except Exception as e:
            print(f"Invalid UMA lnurlp request: {e}")
            abort(
                400,
                {
                    "status": "ERROR",
                    "reason": f"Invalid UMA lnurlp request: {e}",
                },
            )

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
        callback = self._get_complete_url(PAY_REQUEST_CALLBACK + user.id)

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

    def _create_metadata(self, user: User) -> str:
        metadata = [
            ["text/plain", f"Pay to {self.config.get_uma_domain()} user {user.name}"],
            ["text/identifier", user.get_uma_address(self.config)],
        ]
        return json.dumps(metadata)

    def _get_complete_url(self, path: str) -> str:
        return f"https://{self.config.get_uma_domain()}{path}"
