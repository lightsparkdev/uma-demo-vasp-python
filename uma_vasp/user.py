from dataclasses import dataclass
from typing import Optional
from uma import KycStatus

from uma_vasp.config import Config


@dataclass
class User:
    id: str
    uma_user_name: str
    kyc_status: KycStatus
    email_address: Optional[str]
    name: Optional[str]
    currencies: list[str]

    def get_uma_address(self, config: Config) -> str:
        return f"${self.uma_user_name}@{config.get_uma_domain()}"
