from datetime import datetime, timedelta
from typing import Any, Optional
import jwt
from lightspark import Dict
from uma_vasp.config import Config
from uma_vasp.user import User


def create_jwt(user: User, config: Config, expiry_seconds: Optional[int]):
    claims: Dict[str, Any] = {
        "sub": user.id,
        "aud": config.get_uma_domain(),
        "iss": config.get_uma_domain(),
        "address": user.get_uma_address(config),
    }
    if expiry_seconds:
        claims["exp"] = datetime.timestamp(
            datetime.now() + timedelta(seconds=expiry_seconds)
        )
    return jwt.encode(
        claims,
        config.require_nwc_jwt_private_key(),
        algorithm="ES256",
    )
