from typing import Any, Dict, Optional, Union

import aiohttp
from tenacity import (
    AsyncRetrying,
    retry_any,
    retry_if_exception,
    retry_if_exception_type,
    stop_after_attempt,
    stop_after_delay,
    wait_random_exponential,
)

from ..base import BaseHttpClient
from ..errors import RateLimitError
from ..models import ClientConfig, HttpResponse
from ..utils import get_user_agent, log_attempt_number, wait_for_retry_after_header


class HttpClient(BaseHttpClient):
    def __init__(self, config: Optional[Union[ClientConfig, Dict[str, Any]]] = None):
        self.config = ClientConfig.model_validate(config or ClientConfig())
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_owner = False

    def _create_session(self):
        if self.config.session is None:
            connector = aiohttp.TCPConnector(ssl=self.config.http.verify_ssl)
            timeout = aiohttp.ClientTimeout(total=self.config.http.timeout)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=self.config.http.headers,
                **self.config.extra_options,
            )
            self._session_owner = True
        else:
            self._session = self.config.session
            self._session_owner = False

    async def _close_session(self):
        if self._session_owner and self._session:
            await self._session.close()
            self._session = None

    async def __aenter__(self):
        self._create_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._close_session()

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        self._create_session()
        headers = {**self.config.http.headers, **kwargs.get("headers", {})}
        if "User-Agent" not in headers:
            headers["User-Agent"] = get_user_agent()
        kwargs["headers"] = headers

        wait_strategy = wait_for_retry_after_header(wait_random_exponential(min=1))

        stop_strategy = stop_after_attempt(
            self.config.retry.max_retries + 1  # to account for first attempt
        ) | stop_after_delay(self.config.retry.timeout)

        retry_strategy = retry_any(
            retry_if_exception_type(tuple(self.config.retry.exceptions)),
            retry_if_exception(
                lambda e: isinstance(e, aiohttp.ClientResponseError)
                and e.status in self.config.retry.status_codes
            ),
        )

        try:
            async for attempt in AsyncRetrying(
                wait=wait_strategy,
                stop=stop_strategy,
                retry=retry_strategy,
                before_sleep=log_attempt_number,
                reraise=self.config.retry.reraise,
            ):
                with attempt:
                    async with self._session.request(method, url, **kwargs) as response:
                        content = await response.read()
                        if response.status == 429:
                            raise RateLimitError(
                                HttpResponse.from_aiohttp_response(response, content)
                            )
                        response.raise_for_status()
                        return HttpResponse.from_aiohttp_response(response, content)

        finally:
            await self._close_session()

    async def get(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("POST", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("DELETE", url, **kwargs)

    async def put(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("PUT", url, **kwargs)
