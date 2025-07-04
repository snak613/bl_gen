from typing import Any, Dict, Optional

from ..updater import ResourceUpdater
from ..utils import extract_cidr_ips, is_valid_ipv4, is_valid_ipv6


async def get_symantec_ranges(
    url="https://knowledge.broadcom.com/external/article/150693/ip-address-ranges-for-email-symantecclou.html",
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
):
    updater_config = updater_config or {}
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""

    ips = extract_cidr_ips(result.decode())
    return {
        "ipv4": [ip for ip in ips if is_valid_ipv4(ip)],
        "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
    }
