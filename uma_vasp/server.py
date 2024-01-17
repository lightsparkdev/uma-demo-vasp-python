from flask import request
from uma_vasp.config import Config

from uma_vasp.demo.demo_use_service import DemoUserService
from uma_vasp.receiving_vasp import ReceivingVasp
from uma_vasp.app import app

user_service = DemoUserService()
config = Config()

receiving_vasp = ReceivingVasp(
    user_service=user_service,
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


@app.route("/.well-known/lnurlp/<username>")
def handle_lnurlp_request(username: str):
    return receiving_vasp.handle_lnurlp_request(username)
