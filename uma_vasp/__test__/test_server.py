import pytest
from uma_vasp import create_app
from uma_vasp.config import Config


@pytest.fixture()
def client(config):
    app = create_app(config)
    app.config.update({"TESTING": True})
    return app.test_client()


@pytest.fixture()
def config():
    # TODO: Use real values when we have tests that need them.
    return Config(
        api_token_client_id="abcdef",
        api_token_client_secret="123456",
        node_id="nodeid",
        encryption_pubkey_hex="abcdef",
        encryption_privkey_hex="abcdef",
        signing_pubkey_hex="abcdef",
        signing_privkey_hex="abcdef",
    )


def test_lnurlpubkey(client, config):
    response = client.get("/.well-known/lnurlpubkey")
    assert response.status_code == 200
    response_json = response.get_json()
    assert response_json["signingPubKey"] == config.signing_pubkey_hex
    assert response_json["encryptionPubKey"] == config.encryption_pubkey_hex
