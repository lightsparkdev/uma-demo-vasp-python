from typing import Optional
from uma_vasp.user import User
from uma_vasp.user_service import IUserService
from uma import KycStatus

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
            (user for user in USERS if user.uma_user_name == uma_user_name), None
        )

    def get_user_from_id(self, user_id: str) -> Optional[User]:
        return next((user for user in USERS if user.id == user_id), None)
