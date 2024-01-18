import json

from flask import abort
from flask import request as flask_request
from lightspark import LightsparkNode
from lightspark import LightsparkSyncClient as LightsparkClient
from uma import (
    IPublicKeyCache,
)

from uma_vasp.app import app
from uma_vasp.config import Config
from uma_vasp.currencies import (
    CURRENCIES,
    DECIMALS_PER_UNIT,
    MSATS_PER_UNIT,
    RECEIVER_FEES_MSATS,
)
from uma_vasp.user import User
from uma_vasp.user_service import IUserService


class SendingVasp:
    def __init__(
        self,
        user_service: IUserService,
        lightspark_client: LightsparkClient,
        pubkey_cache: IPublicKeyCache,
        config: Config,
    ) -> None:
        self.user_service = user_service
        self.vasp_pubkey_cache = pubkey_cache
        self.lightspark_client = lightspark_client
        self.config = config

    def handle_uma_lookup(self, receiver_uma: str):
        return "OK"

    def handle_uma_payreq(self, callback_uuid: str):
        return "OK"

    def handle_send_payment(self, callback_uuid: str):
        return "OK"


def register_routes(sending_vasp: SendingVasp):
    @app.route("/api/umalookup/<receiver_uma>")
    def handle_uma_lookup(receiver_uma: str):
        return sending_vasp.handle_uma_lookup(receiver_uma)

    @app.route("/api/umapayreq/<callback_uuid>")
    def handle_uma_payreq(callback_uuid: str):
        return sending_vasp.handle_uma_payreq(callback_uuid)

    @app.route("/api/sendpayment/<callback_uuid>", methods=["POST"])
    def handle_send_payment(callback_uuid: str):
        return sending_vasp.handle_send_payment(callback_uuid)
