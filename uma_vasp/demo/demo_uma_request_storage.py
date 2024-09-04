from typing import Dict
import dataclasses

from request_storage import IRequestStorage


@dataclasses.dataclass
class RequestStorage(IRequestStorage):
    def __init__(self):
        self._cache = {}

    def save_request(self, request_id: str, request: Dict):
        self._cache[request_id] = request

    def get_request(self, request_id: str) -> Dict:
        return self._cache.get(request_id)

    def delete_request(self, request_id: str):
        self._cache.pop(request_id, None)

    def get_requests(self) -> Dict:
        return self._cache
