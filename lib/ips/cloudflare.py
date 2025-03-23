import json
from typing import Any, Dict, Optional

from ..updater import ResourceUpdater
from ..utils import is_valid_ipv4, is_valid_ipv6


async def get_cloudflare_ips(
    url="https://api.cloudflare.com/client/v4/ips",
    jd_cloud=True,
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
):
    updater_config = updater_config or {}
    if jd_cloud:
        url += "?networks=jdcloud"

    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or "{}"

    ip_ranges = json.loads(result)["result"]
    cdn = {"ipv4": ip_ranges["ipv4_cidrs"], "ipv6": ip_ranges["ipv6_cidrs"]}

    out = {"cdn": cdn}

    if jd_cloud:
        jd_cloud = {
            "ipv4": [ip for ip in ip_ranges.get("jdcloud_cidrs") if is_valid_ipv4(ip)],
            "ipv6": [ip for ip in ip_ranges.get("jdcloud_cidrs") if is_valid_ipv6(ip)],
        }
        out["jd_cloud"] = jd_cloud
    return out
