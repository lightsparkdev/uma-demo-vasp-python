import os
import jwt
from base64 import b64decode
from typing import Optional

from flask import Response
from uma import KycStatus

from uma_vasp.config import Config
from uma_vasp.user import User
from uma_vasp.user_service import IUserService

_user_name = os.environ.get("LIGHTSPARK_UMA_RECEIVER_USER") or "alice"

USERS = [
    User(
        id="1",
        uma_user_name=_user_name,
        kyc_status=KycStatus.VERIFIED,
        email_address=f"{_user_name}@myvasp.edu",
        name=f"{_user_name.capitalize()} LastName",
        currencies=["SAT", "USD"],
    ),
    User(
        id="2",
        uma_user_name="bob",
        kyc_status=KycStatus.VERIFIED,
        email_address="bob@myvasp.edu",
        name="Bob",
        currencies=["PHP", "SAT"],
    ),
]


class DemoUserService(IUserService):
    def get_user_from_uma_user_name(self, uma_user_name: str) -> Optional[User]:
        return next(
            (
                user
                for user in USERS
                if user.uma_user_name == uma_user_name
                or f"${user.uma_user_name}" == uma_user_name
            ),
            None,
        )

    def get_user_from_id(self, user_id: str) -> Optional[User]:
        return next((user for user in USERS if user.id == user_id), None)

    def parse_bearer_token(self, auth_header: str) -> Optional[User]:
        token = auth_header[len("Bearer ") :]
        config = Config.from_env()  # TODO: Inject the config instead.
        try:
            print(f"Decoding token {token}")
            parsed_jwt = jwt.decode(
                token,
                config.require_nwc_jwt_public_key(),
                algorithms=["ES256"],
                options={"verify_aud": False, "verify_iss": False},
            )
        except jwt.DecodeError as e:
            print(f"Failed to decode JWT: {e}")
            return None
        user_id = parsed_jwt["sub"]
        return self.get_user_from_id(user_id)

    def get_calling_user_from_request(
        self, request_url: str, request_headers: dict
    ) -> Optional[User]:
        expected_password = os.environ.get("LIGHTSPARK_UMA_RECEIVER_USER_PASSWORD")
        if not expected_password:
            print(
                "Skipping authentication because LIGHTSPARK_UMA_RECEIVER_USER_PASSWORD is not set."
            )
            return USERS[0]

        auth_header = request_headers.get("Authorization")
        if not auth_header:
            return None
        if auth_header.startswith("Bearer "):
            return self.parse_bearer_token(auth_header)
        if not auth_header.startswith("Basic "):
            return None

        auth_header = auth_header[len("Basic ") :]
        decoded_auth_header = b64decode(auth_header)
        username, password = decoded_auth_header.decode().split(":")
        user = self.get_user_from_uma_user_name(username)
        if not user:
            return None

        # TODO: Consider using a different password for each user.
        if password != expected_password:
            return None

        return user

    def validate_login(self, username: str, password: str) -> bool:
        user = self.get_user_from_uma_user_name(username)
        if not user:
            return False
        return password == os.environ.get("LIGHTSPARK_UMA_RECEIVER_USER_PASSWORD")
