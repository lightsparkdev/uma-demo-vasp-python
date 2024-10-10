from flask import current_app

from uma.urls import is_domain_local

from uma_vasp.config import Config


def get_uma_configuration_json(config: Config):
    vasp_domain = config.get_uma_domain()
    nwc_domain = config.get_nwc_server_domain()
    protocol = "http" if is_domain_local(nwc_domain) else "https"
    nwc_base = f"{protocol}://{nwc_domain}"
    request_uri = f"{protocol}://{vasp_domain}/api/uma/request_pay_invoice"
    supported_nwc_commands = current_app.config.get(
        "VASP_SUPPORTED_COMMANDS",
        [
            "pay_invoice",
            "make_invoice",
            "lookup_invoice",
            "get_balance",
            "get_budget",
            "get_info",
            "list_transactions",
            "pay_keysend",
            "lookup_user",
            "fetch_quote",
            "execute_quote",
            "pay_to_address",
        ],
    )
    return {
        "name": "Python Demo VASP",
        "authorization_endpoint": f"{nwc_base}/oauth/auth",
        "token_endpoint": f"{nwc_base}/oauth/token",
        "nwc_commands_supported": supported_nwc_commands,
        "uma_major_versions": [0, 1],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "uma_request_endpoint": request_uri,
        "connection_management_endpoint": f"{nwc_base}/connections",
    }
