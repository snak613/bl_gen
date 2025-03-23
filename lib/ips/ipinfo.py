from typing import Any, Dict, Optional

from ..updater import ResourceUpdater
from ..utils import extract_ips, is_valid_ipv4, is_valid_ipv6


async def get_ipinfo_asn_ranges(
    asn: str,
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
):
    url = f"https://ipinfo.io/{asn}"
    updater_config = updater_config or {}

    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""

    ips = extract_ips(result.decode())

    return {
        "ipv4": [ip for ip in ips if is_valid_ipv4(ip)],
        "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
    }
