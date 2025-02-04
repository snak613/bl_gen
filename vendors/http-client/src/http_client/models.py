import socket
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set, Union

import aiohttp
import httpx
from aiohttp.client_exceptions import ClientConnectorDNSError
from pydantic import BaseModel, ConfigDict, Field, computed_field

from .errors import RateLimitError


class RetryErrorResult(BaseModel):
    exception: Union[aiohttp.ClientResponseError, Exception] = Field(alias="_exception")
    num_attempts: int = Field(alias="attempt_number")

    @computed_field
    @property
    def num_retries(self) -> int:
        return self.num_attempts - 1

    model_config = ConfigDict(arbitrary_types_allowed=True, populate_by_name=True)


# remove 429 to be able to parse retry_after
class RetryConfig(BaseModel):
    """Configuration for retry behavior"""

    max_retries: int = Field(default=5, description="Maximum number of retries")
    timeout: float = Field(
        default=30.0, description="Maximum total time for all retries"
    )
    status_codes: Set[int] = Field(
        default={408, 502, 503, 504},
        description="HTTP status codes that should trigger a retry",
    )
    exceptions: Set[type[Exception]] = Field(
        default={
            aiohttp.ClientConnectorError,
            ClientConnectorDNSError,
            socket.gaierror,
            TimeoutError,
            httpx.ConnectTimeout,
            httpx.TransportError,
            RateLimitError,
        },
        description="Exception types that should trigger a retry",
    )
    reraise: bool = Field(
        default=False,
        description="Whether to reraise the last exception after all retries are exhausted",
    )


class HttpClientConfig(BaseModel):
    """Configuration for HTTP client behavior"""

    timeout: Optional[float] = Field(
        default=5, description="Request timeout in seconds"
    )
    verify_ssl: bool = Field(
        default=True, description="Whether to verify SSL certificates"
    )
    proxies: list[str] = Field(default=[], description="List of proxy URLs to use")
    headers: Dict[str, str] = Field(
        default={}, description="Default headers to send with each request"
    )
    follow_redirects: bool = Field(
        default=True, description="Whether to automatically follow redirects"
    )
    max_redirects: int = Field(
        default=20, description="Maximum number of redirects to follow"
    )


class ClientConfig(BaseModel):
    """Main configuration for the HTTP client with retry behavior"""

    http: HttpClientConfig = Field(
        default_factory=HttpClientConfig,
        description="HTTP client specific configuration",
    )
    retry: RetryConfig = Field(
        default_factory=RetryConfig, description="Retry behavior configuration"
    )
    session: Optional[Union[aiohttp.ClientSession, httpx.AsyncClient]] = Field(
        default=None, description="Optional existing client session to use"
    )
    extra_options: Dict[str, Any] = Field(
        default={}, description="Additional client-specific options", alias="extras"
    )

    model_config = ConfigDict(arbitrary_types_allowed=True, populate_by_name=True)


@dataclass
class HttpResponse:
    """Unified response object for both aiohttp and httpx"""

    status_code: int
    reason: str
    url: str
    headers: Dict[str, str]
    content: bytes
    request: Any

    @classmethod
    def from_aiohttp_response(
        cls, response: aiohttp.ClientResponse, content: bytes
    ) -> "HttpResponse":
        return cls(
            status_code=response.status,
            reason=response.reason,
            url=str(response.url),
            headers=dict(response.headers),
            content=content,
            request=response.request_info,
        )

    @classmethod
    def from_httpx_response(
        cls, response: httpx.Response, content: bytes
    ) -> "HttpResponse":
        return cls(
            status_code=response.status_code,
            reason=response.reason_phrase,
            url=str(response.url),
            headers=dict(response.headers),
            content=content,
            request=response.request,
        )
