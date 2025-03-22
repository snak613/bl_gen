from ..updater import ResourceUpdater
import asyncio
import re
from typing import Any, Dict, Optional
from urllib.parse import urljoin

from loguru import logger
from ..utils import is_valid_ipv4, is_valid_ipv6


async def get_blocklist_de(
    url="https://lists.blocklist.de/lists/",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""
    files = re.findall(r"([0-9a-z]+\.txt)\">", result.decode())

    logger.info(f"Found {len(files)} blocklist files in index")

    file_urls = [urljoin(url, file) for file in files]
    tasks = [
        ResourceUpdater(**updater_config, client_config=client_config).get(
            url=file_url, force=force_refresh
        )
        for file_url in file_urls
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    out = {}

    for file, result in zip(files, results):
        if isinstance(result, Exception):
            logger.error(f"Failed to fetch {file}: {str(result)}")
            continue
        key = file[:-4]
        ips = result.decode().splitlines()
        out[key] = {
            "ipv4": [ip for ip in ips if is_valid_ipv4(ip)],
            "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
        }

    return out
