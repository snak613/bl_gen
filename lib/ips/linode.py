from typing import Any, Dict, Optional

from ..updater import ResourceUpdater
from ..utils import is_valid_ipv4, is_valid_ipv6


async def get_linode_ips(
    url="https://geoip.linode.com/",
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
):
    updater_config = updater_config or {}
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""
    ips = [line.split(",")[0] for line in result.decode().splitlines()]
    out = {
        "ipv4": [ip for ip in ips if is_valid_ipv4(ip)],
        "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
    }
    return out
