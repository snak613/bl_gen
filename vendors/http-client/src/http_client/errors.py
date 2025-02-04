from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import HttpResponse


class RateLimitError(Exception):
    def __init__(self, response: "HttpResponse"):
        self.response = response
        message = f"{self.response.status_code} {self.response.reason} for url {self.response.url}"
        super().__init__(message)
