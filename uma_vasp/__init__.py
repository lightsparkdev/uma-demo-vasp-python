from datetime import datetime, timezone
import json

from flask import Flask, jsonify, request
from lightspark import LightsparkSyncClient
from uma import InMemoryNonceCache, InMemoryPublicKeyCache, UnsupportedVersionException

from uma_vasp.config import Config
from uma_vasp.demo.demo_compliance_service import DemoComplianceService
from uma_vasp.demo.demo_user_service import DemoUserService
from uma_vasp.demo.in_memory_sending_vasp_request_cache import (
    InMemorySendingVaspRequestCache,
)
from uma_vasp.receiving_vasp import ReceivingVasp
from uma_vasp.receiving_vasp import register_routes as register_receiving_vasp_routes
from uma_vasp.sending_vasp import SendingVasp
from uma_vasp.sending_vasp import register_routes as register_sending_vasp_routes


def create_app(config=None):
    app = Flask(__name__)
    user_service = DemoUserService()
    if config is None:
        config = Config.from_env()
    pubkey_cache = InMemoryPublicKeyCache()

    host = None
    if config.base_url:
        host = config.base_url.split("://")[1].split("/")[0]
    lightspark_client = LightsparkSyncClient(
        api_token_client_id=config.api_token_client_id,
        api_token_client_secret=config.api_token_client_secret,
        base_url=config.base_url,
        http_host=host,
    )
    compliance_service = DemoComplianceService(lightspark_client, config)
    nonce_cache = InMemoryNonceCache(datetime.now(timezone.utc))

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
    )

    @app.route("/.well-known/lnurlpubkey")
    def handle_public_key_request():
        return {
            "signingPubKey": config.signing_pubkey_hex,
            "encryptionPubKey": config.encryption_pubkey_hex,
        }

    @app.route("/api/uma/utxoCallback", methods=["POST"])
    def handle_utxo_callback():
        print(f"Received UTXO callback for {request.args.get('txid')}")
        print(request.json)
        return "OK"

    @app.errorhandler(UnsupportedVersionException)
    def unsupported_version(e):
        return jsonify(json.loads(e.to_json())), 412

    register_receiving_vasp_routes(app, receiving_vasp)
    register_sending_vasp_routes(app, sending_vasp)
    return app
