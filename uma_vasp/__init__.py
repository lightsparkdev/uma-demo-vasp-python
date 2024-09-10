import json
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request
from lightspark import LightsparkSyncClient
from uma import (
    InMemoryNonceCache,
    InMemoryPublicKeyCache,
    InvalidSignatureException,
    PostTransactionCallback,
    UnsupportedVersionException,
    create_pubkey_response,
    fetch_public_key_for_vasp,
    verify_post_transaction_callback_signature,
)

from uma_vasp.config import Config
from uma_vasp.demo.demo_compliance_service import DemoComplianceService
from uma_vasp.demo.demo_user_service import DemoUserService
from uma_vasp.demo.in_memory_sending_vasp_request_cache import (
    InMemorySendingVaspRequestCache,
)
from uma_vasp.demo.demo_uma_request_storage import RequestStorage
from uma_vasp.receiving_vasp import ReceivingVasp
from uma_vasp.receiving_vasp import register_routes as register_receiving_vasp_routes
from uma_vasp.sending_vasp import SendingVasp
from uma_vasp.sending_vasp import register_routes as register_sending_vasp_routes
from uma_vasp.uma_exception import UmaException


def create_app(config=None, lightspark_client=None):
    app = Flask(__name__)
    user_service = DemoUserService()
    if config is None:
        config = Config.from_env()
    pubkey_cache = InMemoryPublicKeyCache()
    two_weeks_ago = datetime.now(timezone.utc) - timedelta(weeks=2)
    nonce_cache = InMemoryNonceCache(two_weeks_ago)

    host = None
    if config.base_url:
        host = config.base_url.split("://")[1].split("/")[0]
    if lightspark_client is None:
        lightspark_client = LightsparkSyncClient(
            api_token_client_id=config.api_token_client_id,
            api_token_client_secret=config.api_token_client_secret,
            base_url=config.base_url,
            http_host=host,
        )
    compliance_service = DemoComplianceService(lightspark_client, config)

    receiving_vasp = ReceivingVasp(
        user_service=user_service,
        compliance_service=compliance_service,
        lightspark_client=lightspark_client,
        pubkey_cache=pubkey_cache,
        config=config,
        nonce_cache=nonce_cache,
    )

    sending_vasp = SendingVasp(
        user_service=user_service,
        compliance_service=compliance_service,
        lightspark_client=lightspark_client,
        pubkey_cache=pubkey_cache,
        request_cache=InMemorySendingVaspRequestCache(),
        config=config,
        nonce_cache=nonce_cache,
        uma_request_storage=RequestStorage(),
    )

    @app.route("/.well-known/lnurlpubkey")
    def handle_public_key_request():
        return create_pubkey_response(
            config.signing_cert_chain, config.encryption_cert_chain
        ).to_dict()

    @app.route("/.well-known/uma-configuration")
    def handle_uma_configuration():
        return jsonify(
            {
                "uma_major_versions": [0, 1],
                "uma_request_endpoint": config.get_complete_url(
                    "/api/uma/request_pay_invoice"
                ),
            }
        )

    @app.route("/api/uma/utxoCallback", methods=["POST"])
    def handle_utxo_callback():
        print(f"Received UTXO callback for {request.args.get('txid')}:")
        try:
            tx_callback = PostTransactionCallback.from_json(json.dumps(request.json))
        except Exception as e:
            raise UmaException(
                status_code=400, message=f"Error parsing UTXO callback: {e}"
            )

        print(tx_callback.to_json())

        if tx_callback.vasp_domain:
            other_vasp_pubkeys = fetch_public_key_for_vasp(
                vasp_domain=tx_callback.vasp_domain,
                cache=pubkey_cache,
            )
            try:
                verify_post_transaction_callback_signature(
                    tx_callback, other_vasp_pubkeys, nonce_cache
                )
            except InvalidSignatureException as e:
                raise UmaException(
                    f"Error verifying post-tx callback signature: {e}", 424
                )

        return "OK"

    @app.errorhandler(UmaException)
    def invalid_api_usage(e):
        return jsonify(e.to_dict()), e.status_code

    @app.errorhandler(UnsupportedVersionException)
    def unsupported_version(e):
        return jsonify(json.loads(e.to_json())), 412

    register_receiving_vasp_routes(app, receiving_vasp)
    register_sending_vasp_routes(app, sending_vasp)
    return app
