import json
from typing import Any, Dict, Optional

from loguru import logger

from ..updater import ResourceUpdater
from ..utils import is_valid_ipv4, is_valid_ipv6


async def get_github_ips(
    url="https://api.github.com/meta",
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
):
    updater_config = updater_config or {}
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b"{}"
    ranges = json.loads(result)

    if not ranges:
        logger.warning(f"[!] Retrieved dictionary empty: {url}")
        return {}

    results = {}
    for service, ip_ranges in ranges.items():
        if not isinstance(ip_ranges, list):
            continue

        service_name: str = service

        if "/" in service_name or "\\" in service_name:
            continue

        out = {
            "ipv4": list([ip for ip in ip_ranges if is_valid_ipv4(ip)]),
            "ipv6": list([ip for ip in ip_ranges if is_valid_ipv6(ip)]),
        }

        if out["ipv4"] or out["ipv6"]:
            results[service_name] = out

    return results
