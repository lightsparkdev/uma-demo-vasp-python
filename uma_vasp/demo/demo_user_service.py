import os
from base64 import b64decode
from typing import Optional

from uma import KycStatus

from uma_vasp.user import User
from uma_vasp.user_service import IUserService

USERS = [
    User(
        id="1",
        uma_user_name="alice",
        kyc_status=KycStatus.VERIFIED,
        email_address="alice@myvasp.edu",
        name="Alice",
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
