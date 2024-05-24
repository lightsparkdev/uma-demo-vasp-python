from base64 import b64encode
from dataclasses import dataclass
import os
from typing import List, Optional
from uma import KycStatus

from uma_vasp.config import Config


@dataclass
class User:
    id: str
    uma_user_name: str
    kyc_status: KycStatus
    email_address: Optional[str]
    name: Optional[str]
    currencies: List[str]

    def get_uma_address(self, config: Config) -> str:
        return f"${self.uma_user_name}@{config.get_uma_domain()}"

    def get_non_uma_lnurl_address(self, config: Config) -> str:
        return f"{self.uma_user_name}@{config.get_uma_domain()}"
    
    def get_expected_basic_auth(self) -> str:
        expected_password = os.environ.get("LIGHTSPARK_UMA_RECEIVER_USER_PASSWORD")
        if not expected_password:
            return ""
        return b64encode(f"{self.uma_user_name}:{expected_password}".encode()).decode()
