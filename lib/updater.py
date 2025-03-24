import asyncio
import hashlib
import time
from http import HTTPStatus
from pathlib import Path
from tempfile import gettempdir
from typing import Dict, Optional
from urllib.parse import urlparse

from appdirs import user_cache_dir
from http_client import AioHttpClient, ClientConfig, ClientType, RetryErrorResult
from loguru import logger
from tenacity import RetryError
import os


def url_to_filename(url):
    parsed_url = urlparse(url)
    normalized_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    if parsed_url.query:
        normalized_url += "?" + "&".join(sorted(parsed_url.query.split("&")))

    url_hash = hashlib.sha256(normalized_url.encode()).hexdigest()
    return url_hash


class ResourceUpdater:
    def __init__(
        self,
        url: Optional[str] = None,
        app_name: str = "python-resource-updater",
        version: Optional[str] = None,
        cache_ttl: int = 5 * 3600 * 24,  # 5 days
        cache_dir: Optional[Path] = None,
        use_system_cache: bool = True,
        in_memory_fallback: bool = True,
        http_client: Optional[ClientType] = None,
        client_config: Optional[ClientConfig] = None,
    ):
        self.url = url
        self.cache_ttl = cache_ttl
        self.in_memory_fallback = in_memory_fallback
        self.app_name = app_name
        self.version = version

        self.client_config = ClientConfig.model_validate(client_config or {})
        self._session_owner = None
        self.http_client = http_client

        self._setup_storage(cache_dir, use_system_cache)

        self._memory_cache: Dict[str, bytes] = {}
        self._memory_expiry: Dict[str, float] = {}
        self._etag: Optional[str] = None
        self._last_modified: Optional[float] = None
        self._lock = asyncio.Lock()

    def _create_session(self):
        if not self.http_client and self.client_config.session is None:
            import aiohttp

            self.client_config.session = aiohttp.ClientSession()
            self._session_owner = True
        else:
            self._session_owner = False

        self.http_client = self.http_client or AioHttpClient(self.client_config)

    def _setup_storage(self, cache_dir: Optional[Path], use_system_cache: bool):
        if cache_dir:
            # logger.info(f"using cache Dir: {cache_dir}")
            self.cache_dir = cache_dir
        elif use_system_cache:
            sys_cache = Path(user_cache_dir(self.app_name, version=self.version))

            self.cache_dir = sys_cache
        else:
            self.cache_dir = Path(gettempdir())

        self._writable = self._check_write_access()

    def _check_write_access(self) -> bool:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            test_file = self.cache_dir / ".write_test"
            test_file.touch()
            test_file.unlink()
            return True
        except OSError as e:
            logger.info(f"{self.cache_dir} is unwritable: {e}")
            if not self.in_memory_fallback:
                raise RuntimeError(
                    f"No write access to {self.cache_dir} and in-memory fallback disabled"
                ) from None
            return False

    @property
    def resource_path(self) -> Optional[Path]:
        return self.cache_dir / self.resource_name if self.url else None

    @property
    def resource_name(self):
        return url_to_filename(self.url) if self.url else None

    @property
    def etag_path(self) -> Optional[Path]:
        return self.cache_dir / f"{self.resource_name}.etag" if self.url else None

    @property
    def modified_path(self) -> Optional[Path]:
        return (
            self.cache_dir / f"{self.resource_name}.last_modified" if self.url else None
        )

    async def get(
        self,
        url: Optional[str] = None,
        force: bool = False,
        **kwargs,
    ) -> bytes:
        if url:
            self.url = url

        async with self._lock:
            try:
                return await self._fetch_impl(force, **kwargs)
            except Exception as e:
                if self._memory_cache is not None:
                    logger.warning(f"Using stale cache after error: {str(e)}")
                    return self._memory_cache.get(self.resource_name)
                raise

    async def _fetch_impl(
        self,
        force: bool = False,
        **kwargs,
    ) -> bytes:
        if not force and self._memory_valid:
            logger.debug(f"Using valid memory cache for {self.url.strip()}")
            return self._memory_cache[self.resource_name]

        if not force and self._disk_cache_valid and self._writable:
            logger.debug(f"Using valid disk cache for {self.url.strip()}")
            return self._load_from_disk()

        # logger.debug(f"Force: {force}, valid cache : {self._disk_cache_valid}, writable: {self._writable}")
        logger.debug(f"Fetching from network for {self.url.strip()}")
        data = await self._fetch_from_source(**kwargs)

        if self._writable:
            await self._update_disk_cache(data)
        self._update_memory_cache(data)

        return data

    async def _fetch_from_source(self, **kwargs) -> bytes:
        """Fetch resource with cache validation"""

        headers = self._create_cache_headers()
        self._create_session()

        try:
            async with self.http_client as client:
                response = await client.get(self.url, headers=headers, **kwargs)
                if response.status_code == HTTPStatus.NOT_MODIFIED:
                    logger.info(
                        f"Received {HTTPStatus.NOT_MODIFIED}, Cache valid for {self.url}"
                    )
                    cached_data = self._load_from_cache()
                    self._update_memory_cache(cached_data)  # This updates the expiry time

                    if self._writable and self.resource_path.exists():
                        current_time = time.time()
                        os.utime(self.resource_path, (current_time, current_time))
                
                    return cached_data
                   

                if response.status_code == HTTPStatus.OK:
                    data = response.content
                    self._update_cache_headers_from_response(response.headers)
                    logger.info(f"Successfully updated from {self.url}")
                    return data

        except Exception as e:
            if isinstance(e, RetryError):
                retry_result = RetryErrorResult(**e.last_attempt.__dict__)
                logger.info(f"Request failed for {self.url} with {retry_result}")
            else:
                logger.warning(f"Failed to fetch {self.url}: {str(e)}")
            return self._load_from_cache()

        finally:
            if self._session_owner and not self.client_config.session.closed:
                await self.client_config.session.close()

    def _create_cache_headers(self) -> dict:
        headers = {}
        if self._writable and not self._disk_cache_expired:
            if etag := self._read_etag():
                headers["If-None-Match"] = etag
            if modified := self._read_last_modified():
                headers["If-Modified-Since"] = modified
        return headers

    def _update_cache_headers_from_response(self, headers: dict):
        self._etag = headers.get("ETag")
        self._last_modified = headers.get("Last-Modified")

    def _load_from_cache(self) -> bytes:
        if self._memory_cache is not None and self.resource_name in self._memory_cache:
            logger.debug("Loading from memory cache")
            return self._memory_cache[self.resource_name]
        if self._writable and self.resource_path.exists():
            logger.debug("Loading from disk cache")
            return self.resource_path.read_bytes()
        raise RuntimeError("No cached data available and all sources failed")

    async def _update_disk_cache(self, data: bytes):
        """Atomically update disk cache"""
        temp_path = self.resource_path.with_suffix(".tmp")
        try:
            # Write to temp file first
            temp_path.write_bytes(data)

            # Update metadata files
            if self._etag:
                self.etag_path.write_text(self._etag)
            if self._last_modified:
                self.modified_path.write_text(self._last_modified)

            # Atomic replace
            # logger.info(f"caching  to : {self.resource_path}")
            temp_path.replace(self.resource_path)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def _update_memory_cache(self, data: bytes):
        """Update in-memory cache with expiration"""
        self._memory_cache[self.resource_name] = data
        self._memory_expiry[self.resource_name] = time.time() + self.cache_ttl

    @property
    def _memory_valid(self) -> bool:
        return (
            self.resource_name in self._memory_cache
            and time.time() < self._memory_expiry.get(self.resource_name, 0)
        )

    @property
    def _disk_cache_valid(self) -> bool:
        return self.resource_path.exists() and not self._disk_cache_expired

    @property
    def _disk_cache_expired(self) -> bool:
        try:
            return (time.time() - self.resource_path.stat().st_mtime) > self.cache_ttl
        except FileNotFoundError:
            return True

    def _load_from_disk(self) -> bytes:
        """Read from disk cache"""
        return self.resource_path.read_bytes()

    def _read_etag(self) -> Optional[str]:
        try:
            return self.etag_path.read_text().strip()
        except FileNotFoundError:
            return None

    def _read_last_modified(self) -> Optional[str]:
        try:
            return self.modified_path.read_text().strip()
        except FileNotFoundError:
            return None
