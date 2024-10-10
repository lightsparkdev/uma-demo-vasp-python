from typing import Optional


class UmaException(Exception):
    def __init__(self, message: str, status_code: int, code: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code

    def __str__(self):
        return f"UmaException: {self.message}, Status Code: {self.status_code}"

    def to_dict(self):
        json_dict = {"reason": self.message, "status": "ERROR"}
        if self.code:
            json_dict["code"] = self.code
        return json_dict
