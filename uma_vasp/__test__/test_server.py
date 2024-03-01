import pytest
import uma
from lightspark.utils.currency_amount import amount_as_msats

from uma_vasp import create_app
from uma_vasp.__test__.fake_lightspark_client import FakeLightsparkClient
from uma_vasp.config import Config
from uma_vasp.currencies import MSATS_PER_UNIT, RECEIVER_FEES_MSATS


@pytest.fixture()
def client(config, fake_lightspark_client):
    app = create_app(config, fake_lightspark_client)
    app.config.update({"TESTING": True})
    return app.test_client()


@pytest.fixture()
def fake_lightspark_client():
    return FakeLightsparkClient()


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


def test_payreq_with_receiving_amount(client, fake_lightspark_client):
    payreq = uma.create_pay_request(
        receiving_currency_code="USD",
        is_amount_in_receiving_currency=True,
        amount=100,
        payer_identifier="$alice@vasp.com",
        payer_name=None,
        payer_email=None,
        payer_compliance=None,
        requested_payee_data=None,
    )
    response = client.post(
        "/api/uma/payreq/1",
        json=payreq.to_dict(),
    )
    assert response.status_code == 200
    payreq_response = uma.parse_pay_req_response(response.get_data(as_text=True))
    assert payreq_response.encoded_invoice is not None

    invoice = fake_lightspark_client.last_created_invoice
    assert invoice is not None
    invoice_amount = amount_as_msats(invoice.data.amount)
    assert invoice_amount == 100 * MSATS_PER_UNIT["USD"] + RECEIVER_FEES_MSATS["USD"]


def test_payreq_with_msats(client, fake_lightspark_client):
    payreq = uma.create_pay_request(
        receiving_currency_code="USD",
        is_amount_in_receiving_currency=False,
        amount=1_000_000,
        payer_identifier="$alice@vasp.com",
        payer_name=None,
        payer_email=None,
        payer_compliance=None,
        requested_payee_data=None,
    )
    response = client.post(
        "/api/uma/payreq/1",
        json=payreq.to_dict(),
    )
    assert response.status_code == 200
    payreq_response = uma.parse_pay_req_response(response.get_data(as_text=True))
    assert payreq_response.encoded_invoice is not None

    invoice = fake_lightspark_client.last_created_invoice
    assert invoice is not None
    invoice_amount = amount_as_msats(invoice.data.amount)
    assert invoice_amount == 1_000_000
