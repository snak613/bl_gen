from typing import Any, Dict, Optional

from ..updater import ResourceUpdater
from ..utils import is_valid_ipv4, is_valid_ipv6


async def get_digitalocean_ips(
    url="https://www.digitalocean.com/geo/google.csv",
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
):
    updater_config = updater_config or {}
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""

    ranges = [line.split(",")[0] for line in result.decode().splitlines() if line]

    return {
        "ipv4": [ip for ip in ranges if is_valid_ipv4(ip)],
        "ipv6": [ip for ip in ranges if is_valid_ipv6(ip)],
    }
