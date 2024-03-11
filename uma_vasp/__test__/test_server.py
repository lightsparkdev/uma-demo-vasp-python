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
    cert = """-----BEGIN CERTIFICATE-----
        MIIB1zCCAXygAwIBAgIUGN3ihBj1RnKoeTM/auDFnNoThR4wCgYIKoZIzj0EAwIw
        QjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCmNhbGlmb3JuaWExDjAMBgNVBAcMBWxv
        cyBhMQ4wDAYDVQQKDAVsaWdodDAeFw0yNDAzMDUyMTAzMTJaFw0yNDAzMTkyMTAz
        MTJaMEIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApjYWxpZm9ybmlhMQ4wDAYDVQQH
        DAVsb3MgYTEOMAwGA1UECgwFbGlnaHQwVjAQBgcqhkjOPQIBBgUrgQQACgNCAARB
        nFRn6lY/ABD9YU+F6IWsmcIbjo1BYkEXX91e/SJE/pB+Lm+j3WYxsbF80oeY2o2I
        KjTEd21EzECQeBx6reobo1MwUTAdBgNVHQ4EFgQUU87LnQdiP6XIE6LoKU1PZnbt
        bMwwHwYDVR0jBBgwFoAUU87LnQdiP6XIE6LoKU1PZnbtbMwwDwYDVR0TAQH/BAUw
        AwEB/zAKBggqhkjOPQQDAgNJADBGAiEAvsrvoeo3rbgZdTHxEUIgP0ArLyiO34oz
        NlwL4gk5GpgCIQCvRx4PAyXNV9T6RRE+3wFlqwluOc/pPOjgdRw/wpoNPQ==
        -----END CERTIFICATE-----"""
    pubkey_hex = "04419c5467ea563f0010fd614f85e885ac99c21b8e8d416241175fdd5efd2244fe907e2e6fa3dd6631b1b17cd28798da8d882a34c4776d44cc4090781c7aadea1b"
    # TODO: Use real values when we have tests that need them.
    return Config(
        api_token_client_id="abcdef",
        api_token_client_secret="123456",
        node_id="nodeid",
        encryption_cert_chain=cert,
        encryption_pubkey_hex=pubkey_hex,
        encryption_privkey_hex="abcdef",
        signing_cert_chain=cert,
        signing_pubkey_hex=pubkey_hex,
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
        uma_major_version=1,
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
        uma_major_version=1,
    )
    print(payreq)
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

def test_v0_payreq(client, fake_lightspark_client):
    payreq = uma.create_pay_request(
        receiving_currency_code="USD",
        is_amount_in_receiving_currency=True,
        amount=100,
        payer_identifier="$alice@vasp.com",
        payer_name=None,
        payer_email=None,
        payer_compliance=None,
        requested_payee_data=None,
        uma_major_version=0,
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
