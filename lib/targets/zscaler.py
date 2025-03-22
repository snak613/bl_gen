from ..updater import ResourceUpdater
from typing import Any, Dict, Optional

from ..utils import extract_ips, sort_ips, is_valid_ipv4, is_valid_ipv6


async def get_zscaler_ips(
    url="https://config.zscaler.com/api/getdata/zscalerthree.net/all/cenr",
    params={"site": "config.zscaler.com"},
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh, params=params) or b""
    ips = extract_ips(result.decode())

    return {
        "ipv4": sort_ips([ip for ip in ips if is_valid_ipv4(ip)]),
        "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
    }
