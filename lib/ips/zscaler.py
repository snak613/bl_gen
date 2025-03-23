from typing import Any, Dict, Optional

from ..updater import ResourceUpdater
from ..utils import extract_ips, is_valid_ipv4, is_valid_ipv6, sort_ips


async def get_zscaler_ips(
    url="https://config.zscaler.com/api/getdata/zscalerthree.net/all/cenr",
    params=None,
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
):
    params = params or {"site": "config.zscaler.com"}
    updater = ResourceUpdater(
        **(updater_config or {}), client_config=(client_config or {})
    )
    result = await updater.get(url, force=force_refresh, params=params) or b""
    ips = extract_ips(result.decode())

    return {
        "ipv4": sort_ips([ip for ip in ips if is_valid_ipv4(ip)]),
        "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
    }
