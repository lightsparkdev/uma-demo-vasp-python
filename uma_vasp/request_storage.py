from typing import Dict

from abc import ABC, abstractmethod


class IRequestStorage(ABC):
    @abstractmethod
    def save_request(self, request_id: str, request: Dict):
        pass

    @abstractmethod
    def get_request(self, request_id: str) -> Dict:
        pass

    @abstractmethod
    def delete_request(self, request_id: str):
        pass

    @abstractmethod
    def get_requests(self) -> Dict:
        pass
