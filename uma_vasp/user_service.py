from abc import ABC, abstractmethod
from typing import Optional

from uma_vasp.user import User


class IUserService(ABC):
    @abstractmethod
    def get_user_from_uma_user_name(self, uma_user_name: str) -> Optional[User]:
        pass

    @abstractmethod
    def get_user_from_id(self, user_id: str) -> Optional[User]:
        pass
