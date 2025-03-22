from ..updater import ResourceUpdater
from typing import Any, Dict, Optional, Set
from collections import defaultdict
from ..utils import is_valid_ip
import json


async def get_isc_thread_category(
    url: str = "https://isc.sans.edu/api/threatcategory/research?json",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
) -> Dict[str, Dict[str, Set[str]]]:
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b"[]"

    ranges = json.loads(result.decode())

    processed_data = defaultdict(lambda: {"ipv4": [], "ipv6": []})

    for item in ranges:
        ip_type = item.get("type")
        if not ip_type or "/" in ip_type or "\\" in ip_type:
            continue

        for ip_version in ["ipv4", "ipv6"]:
            if ip_version in item:
                ip = item[ip_version]
                if is_valid_ip(ip):
                    processed_data[ip_type][ip_version].append(ip)

    return {
        ip_type: {"ipv4": ips["ipv4"], "ipv6": ips["ipv6"]}
        for ip_type, ips in processed_data.items()
    }
