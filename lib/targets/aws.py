from ..updater import ResourceUpdater
from typing import Any, Dict, Optional

from loguru import logger
import json


def process_aws_ip_ranges(ip_ranges):
    return {
        service.lower(): {
            "ipv4": [
                r["ip_prefix"]
                for r in ip_ranges["prefixes"]
                if r["service"].lower() == service.lower()
            ],
            "ipv6": [
                r["ipv6_prefix"]
                for r in ip_ranges["ipv6_prefixes"]
                if r["service"].lower() == service.lower()
            ],
        }
        for service in {
            r["service"].lower()
            for r in ip_ranges["prefixes"] + ip_ranges["ipv6_prefixes"]
        }
    }


async def get_aws_ips(
    url="https://ip-ranges.amazonaws.com/ip-ranges.json",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b"{}"

    ip_ranges = json.loads(result)

    if not ip_ranges:
        logger.warning(f"[!] Retrieved dictionary empty for {url}")
        return {}

    if not ip_ranges["prefixes"]:
        logger.warning(f"[!] Retrieved dictionary key prefixes missing for {url}")
        return {}

    return process_aws_ip_ranges(ip_ranges)
