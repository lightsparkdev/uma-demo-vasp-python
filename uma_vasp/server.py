from flask import request
from lightspark import LightsparkSyncClient

from uma_vasp.app import app
from uma_vasp.config import Config
from uma_vasp.demo.demo_user_service import DemoUserService
from uma_vasp.receiving_vasp import ReceivingVasp
from uma_vasp.receiving_vasp import register_routes as register_receiving_vasp_routes

user_service = DemoUserService()
config = Config()
lightspark_client = LightsparkSyncClient(
    api_token_client_id=config.api_token_client_id,
    api_token_client_secret=config.api_token_client_secret,
    http_host=config.base_url,
)

receiving_vasp = ReceivingVasp(
    user_service=user_service,
    lightspark_client=lightspark_client,
    config=config,
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


register_receiving_vasp_routes(receiving_vasp)
