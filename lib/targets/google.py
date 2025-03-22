from ..updater import ResourceUpdater
import re
from typing import Any, Dict, Optional

from loguru import logger
import json


def process_google_ip_ranges(ip_ranges):
    return {
        re.sub(r"\s+", "_", service.lower()): {
            "ipv4": [
                r["ipv4Prefix"]
                for r in ip_ranges["prefixes"]
                if r["service"].lower() == service.lower() and "ipv4Prefix" in r
            ],
            "ipv6": [
                r["ipv6Prefix"]
                for r in ip_ranges["prefixes"]
                if r["service"].lower() == service.lower() and "ipv6Prefix" in r
            ],
        }
        for service in {r["service"].lower() for r in ip_ranges["prefixes"]}
    }


async def get_google_ips(
    url="https://www.gstatic.com/ipranges/cloud.json",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b"{}"

    ip_ranges: Dict[str, Any] = json.loads(result)
    if not ip_ranges.get("prefixes"):
        logger.warning(f"[!] Retrieved dictionary empty for {url}")
        return {}

    return process_google_ip_ranges(ip_ranges)
