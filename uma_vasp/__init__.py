import json
from typing import Optional
import jwt
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse, unquote_plus

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
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

from uma_vasp.auth import create_jwt
from uma_vasp.config import Config
from uma_vasp.currencies import CURRENCIES
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
from uma_vasp.uma_auth_adapter import UmaAuthAdapter
from flask_cors import CORS
from uma_vasp.uma_auth_adapter import (
    register_routes as register_uma_auth_adapter_routes,
)
from uma_vasp.uma_configuration import get_uma_configuration_json
from uma_vasp.uma_exception import UmaException
from uma_vasp.user import User


def create_app(config_override: Optional[Config] = None, lightspark_client=None):
    app = Flask(__name__)

    CORS(
        app,
        resources={r"/.well-known/*": {"origins": "*"}},
        supports_credentials=True,
    )
    user_service = DemoUserService()
    config = config_override if config_override is not None else Config.from_env()
    app.secret_key = config.secret_key
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

    uma_auth_adapter = UmaAuthAdapter(
        lightspark_client=lightspark_client,
        config=config,
        user_service=user_service,
        sending_vasp=sending_vasp,
    )

    @app.route("/.well-known/lnurlpubkey")
    def handle_public_key_request():
        return create_pubkey_response(
            config.signing_cert_chain, config.encryption_cert_chain
        ).to_dict()

    @app.route("/.well-known/uma-configuration")
    def handle_uma_configuration_request():
        return jsonify(get_uma_configuration_json(config))

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

    # Route for handling the login page logic
    @app.route("/login", methods=["GET", "POST"])
    def login():
        def handle_redirect_url(redirect_url: str, user: User):
            parsed_url = urlparse(redirect_url)
            expected_nwc_domain = config.get_nwc_server_domain()
            if parsed_url.netloc != expected_nwc_domain:
                print(f"Invalid redirect URL: {redirect_url}")
                return (
                    jsonify({"error": f"Invalid redirect URL: {parsed_url.netloc}"}),
                    400,
                )

            user_nwc_jwt = create_jwt(user, config, 600)
            query_params = parse_qs(parsed_url.query)
            query_params["token"] = [user_nwc_jwt]
            first_currency = CURRENCIES[user.currencies[0]]
            query_params["currency"] = [
                json.dumps(
                    {
                        "name": first_currency.name,
                        "symbol": first_currency.symbol,
                        "decimals": first_currency.decimals,
                        "code": first_currency.code,
                    }
                )
            ]
            new_query_string = urlencode(query_params, doseq=True)
            new_url = urlunparse(parsed_url._replace(query=new_query_string))
            return redirect(str(new_url))

        error = None
        if request.method == "POST":
            if (
                user_service.validate_login(
                    request.form["username"], request.form["password"]
                )
                == False
            ):
                error = "Invalid Credentials. Please try again."
            else:
                user = user_service.get_user_from_uma_user_name(
                    request.form["username"]
                )
                assert user is not None
                session["uid"] = user.id
                redirect_url = request.args.get("redirect_uri")
                if redirect_url:
                    return handle_redirect_url(unquote_plus(redirect_url), user)
                return redirect(url_for("home"))

        if "uid" in session:
            user = user_service.get_user_from_id(session["uid"])
            if not user:
                session.pop("uid", None)
                return render_template("login.html", error=error)

            redirect_url = request.args.get("redirect_uri")
            if redirect_url:
                return handle_redirect_url(unquote_plus(redirect_url), user)

            return redirect(url_for("home"))
        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        session.pop("uid", None)
        return redirect(url_for("login"))

    @app.route("/")
    def home():
        if "uid" not in session:
            return redirect(url_for("login"))
        user = user_service.get_user_from_id(session["uid"])
        if user is None:
            return redirect(url_for("login"))
        return f"Logged in as {user.get_uma_address(config)}."

    @app.errorhandler(UmaException)
    def invalid_api_usage(e):
        return jsonify(e.to_dict()), e.status_code

    @app.errorhandler(UnsupportedVersionException)
    def unsupported_version(e):
        return jsonify(json.loads(e.to_json())), 412

    register_receiving_vasp_routes(app, receiving_vasp)
    register_sending_vasp_routes(app, sending_vasp)
    register_uma_auth_adapter_routes(app, uma_auth_adapter)
    return app
