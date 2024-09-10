import os
from typing import Optional

from flask import request
from lightspark.objects.ComplianceProvider import ComplianceProvider
from uma.urls import is_domain_local


class Config:
    """Extracts required environment variables and exposes them to the rest of the app."""

    @classmethod
    def from_env(cls):
        api_token_client_id = require_env("LIGHTSPARK_API_TOKEN_CLIENT_ID")
        api_token_client_secret = require_env("LIGHTSPARK_API_TOKEN_CLIENT_SECRET")
        node_id = require_env("LIGHTSPARK_UMA_NODE_ID")
        encryption_cert_chain = require_env("LIGHTSPARK_UMA_ENCRYPTION_CERT_CHAIN")
        encryption_pubkey_hex = require_env("LIGHTSPARK_UMA_ENCRYPTION_PUBKEY")
        encryption_privkey_hex = require_env("LIGHTSPARK_UMA_ENCRYPTION_PRIVKEY")
        signing_cert_chain = require_env("LIGHTSPARK_UMA_SIGNING_CERT_CHAIN")
        signing_pubkey_hex = require_env("LIGHTSPARK_UMA_SIGNING_PUBKEY")
        signing_privkey_hex = require_env("LIGHTSPARK_UMA_SIGNING_PRIVKEY")
        base_url = os.environ.get("LIGHTSPARK_EXAMPLE_BASE_URL")
        osk_node_signing_key_password = os.environ.get(
            "LIGHTSPARK_UMA_OSK_NODE_SIGNING_KEY_PASSWORD"
        )
        remote_signing_node_master_seed = os.environ.get(
            "LIGHTSPARK_UMA_REMOTE_SIGNING_NODE_MASTER_SEED"
        )
        secret_key = os.environ.get("COOKIE_SECRET")
        nwc_jwt_private_key = os.environ.get("NWC_JWT_PRIVKEY")
        nwc_jwt_public_key = os.environ.get("NWC_JWT_PUBKEY")
        compliance_provider = None
        try:
            compliance_env = os.environ.get("LIGHTSPARK_UMA_COMPLIANCE_PROVIDER")
            if compliance_env:
                compliance_provider = ComplianceProvider[compliance_env]
        except KeyError:
            # leave it as None
            pass
        return Config(
            api_token_client_id,
            api_token_client_secret,
            node_id,
            encryption_cert_chain,
            encryption_pubkey_hex,
            encryption_privkey_hex,
            signing_cert_chain,
            signing_pubkey_hex,
            signing_privkey_hex,
            nwc_jwt_private_key,
            nwc_jwt_public_key,
            base_url,
            osk_node_signing_key_password,
            remote_signing_node_master_seed,
            compliance_provider,
            secret_key=secret_key,
        )

    def __init__(
        self,
        api_token_client_id: str,
        api_token_client_secret: str,
        node_id: str,
        encryption_cert_chain: str,
        encryption_pubkey_hex: str,
        encryption_privkey_hex: str,
        signing_cert_chain: str,
        signing_pubkey_hex: str,
        signing_privkey_hex: str,
        nwc_jwt_private_key: Optional[str] = None,
        nwc_jwt_public_key: Optional[str] = None,
        base_url: Optional[str] = None,
        osk_node_signing_key_password: Optional[str] = None,
        remote_signing_node_master_seed: Optional[str] = None,
        compliance_provider: Optional[ComplianceProvider] = None,
        secret_key: Optional[str] = None,
    ):
        self.api_token_client_id = api_token_client_id
        self.api_token_client_secret = api_token_client_secret
        self.node_id = node_id
        self.encryption_cert_chain = encryption_cert_chain
        self.encryption_pubkey_hex = encryption_pubkey_hex
        self.encryption_privkey_hex = encryption_privkey_hex
        self.signing_cert_chain = signing_cert_chain
        self.signing_pubkey_hex = signing_pubkey_hex
        self.signing_privkey_hex = signing_privkey_hex
        self.nwc_jwt_private_key = nwc_jwt_private_key
        self.nwc_jwt_public_key = nwc_jwt_public_key
        self.base_url = base_url
        self.osk_node_signing_key_password = osk_node_signing_key_password
        self.remote_signing_node_master_seed = remote_signing_node_master_seed
        self.compliance_provider = compliance_provider
        self.secret_key = secret_key or os.urandom(32).hex()

    def get_encryption_privkey(self):
        return bytes.fromhex(self.encryption_privkey_hex)

    def get_signing_privkey(self):
        return bytes.fromhex(self.signing_privkey_hex)

    def get_remote_signing_node_master_seed(self):
        return (
            bytes.fromhex(self.remote_signing_node_master_seed)
            if self.remote_signing_node_master_seed
            else None
        )

    def require_nwc_jwt_private_key(self):
        if not self.nwc_jwt_private_key:
            raise MissingEnvironmentVariableException("NWC_JWT_PRIVKEY is not set")
        return self.nwc_jwt_private_key
    
    def require_nwc_jwt_public_key(self):
        if not self.nwc_jwt_public_key:
            raise MissingEnvironmentVariableException("NWC_JWT_PUBKEY is not set")
        return self.nwc_jwt_public_key

    def get_uma_domain(self) -> str:
        uma_domain = os.environ.get("LIGHTSPARK_UMA_VASP_DOMAIN")
        if uma_domain:
            return uma_domain

        parts = request.url_root.split("/")
        return parts[-2]

    def get_nwc_server_domain(self) -> str:
        domain_from_env = os.environ.get("LIGHTSPARK_NWC_SERVER_DOMAIN")
        if domain_from_env:
            return domain_from_env
        return f"nwc.{self.get_uma_domain()}"

    def get_complete_url(self, path: str) -> str:
        domain = self.get_uma_domain()
        protocol = "http" if is_domain_local(domain) else "https"
        return f"{protocol}://{self.get_uma_domain()}{path}"


def require_env(env_var_name):
    value = os.environ.get(env_var_name)
    if value is None:
        raise MissingEnvironmentVariableException(
            f"Missing required environment variable: {env_var_name}"
        )
    return value


class MissingEnvironmentVariableException(Exception):
    pass
