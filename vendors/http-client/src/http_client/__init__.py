from typing import Union

from .aiohttp import HttpClient as AioHttpClient
from .base import BaseHttpClient
from .httpx import HttpClient as HttpxClient
from .models import (
    ClientConfig,
    HttpClientConfig,
    HttpResponse,
    RetryConfig,
    RetryErrorResult,
)

ClientType = Union[AioHttpClient, HttpxClient]

__all__ = [
    "AioHttpClient",
    "BaseHttpClient",
    "ClientConfig",
    "ClientType",
    "HttpClientConfig",
    "HttpResponse",
    "HttpxClient",
    "RetryConfig",
    "RetryErrorResult",
]
