import os

from flask import request
from lightspark import ComplianceProvider


class Config:
    """Extracts required environment variables and exposes them to the rest of the app."""

    def __init__(self):
        self.api_token_client_id = require_env("LIGHTSPARK_API_TOKEN_CLIENT_ID")
        self.api_token_client_secret = require_env("LIGHTSPARK_API_TOKEN_CLIENT_SECRET")
        self.node_id = require_env("LIGHTSPARK_UMA_NODE_ID")
        self.encryption_pubkey_hex = require_env("LIGHTSPARK_UMA_ENCRYPTION_PUBKEY")
        self.encryption_privkey_hex = require_env("LIGHTSPARK_UMA_ENCRYPTION_PRIVKEY")
        self.signing_pubkey_hex = require_env("LIGHTSPARK_UMA_SIGNING_PUBKEY")
        self.signing_privkey_hex = require_env("LIGHTSPARK_UMA_SIGNING_PRIVKEY")
        self.base_url = os.environ.get("LIGHTSPARK_EXAMPLE_BASE_URL")
        self.osk_node_signing_key_password = os.environ.get(
            "LIGHTSPARK_UMA_OSK_NODE_SIGNING_KEY_PASSWORD"
        )
        self.remote_signing_node_master_seed = os.environ.get(
            "LIGHTSPARK_UMA_REMOTE_SIGNING_NODE_MASTER_SEED"
        )
        self.compliance_provider = None
        try:
            compliance_env = os.environ.get("LIGHTSPARK_UMA_COMPLIANCE_PROVIDER")
            self.compliance_provider = ComplianceProvider[compliance_env]
        except KeyError:
            # leave it as None
            pass

    def get_encryption_pubkey(self):
        return bytes.fromhex(self.encryption_pubkey_hex)

    def get_encryption_privkey(self):
        return bytes.fromhex(self.encryption_privkey_hex)

    def get_signing_pubkey(self):
        return bytes.fromhex(self.signing_pubkey_hex)

    def get_signing_privkey(self):
        return bytes.fromhex(self.signing_privkey_hex)

    def get_remote_signing_node_master_seed(self):
        return (
            bytes.fromhex(self.remote_signing_node_master_seed)
            if self.remote_signing_node_master_seed
            else None
        )

    def get_uma_domain(self) -> str:
        uma_domain = os.environ.get("LIGHTSPARK_UMA_VASP_DOMAIN")
        if uma_domain:
            return uma_domain

        parts = request.url_root.split("/")
        return parts[-2]

    def get_complete_url(self, path: str) -> str:
        return f"http://{self.get_uma_domain()}{path}"


def require_env(env_var_name):
    value = os.environ.get(env_var_name)
    if value is None:
        raise MissingEnvironmentVariableException(
            f"Missing required environment variable: {env_var_name}"
        )
    return value


class MissingEnvironmentVariableException(Exception):
    pass
