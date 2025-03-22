from ..updater import ResourceUpdater
from typing import Any, Dict, Optional

from ..utils import is_valid_ipv4, is_valid_ipv6


async def get_ipsum_ips(
    url="https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    threshold=3,
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""
    ips = []
    for line in result.decode().splitlines():
        if not line.startswith("#"):
            parts = line.split()
            if len(parts) == 2:
                ip, count_str = parts
                try:
                    count = int(count_str)
                    if count >= threshold:
                        ips.append(ip)
                except ValueError:
                    continue

    out = {
        "ipv4": [ip for ip in ips if is_valid_ipv4(ip)],
        "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
    }
    return out
