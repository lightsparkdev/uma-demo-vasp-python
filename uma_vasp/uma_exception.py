class UmaException(Exception):
    def __init__(self, message, status_code):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def __str__(self):
        return f"UmaException: {self.message}, Status Code: {self.status_code}"

    def to_dict(self):
        return {"reason": self.message, "status": "ERROR"}
