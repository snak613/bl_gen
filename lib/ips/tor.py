import re
from typing import Any, Dict, Optional

from ..updater import ResourceUpdater
from ..utils import is_valid_ipv4, is_valid_ipv6


async def get_tor_exit_nodes(
    url: str = "https://metrics.torproject.org/collector/recent/exit-lists/",
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
):
    updater = ResourceUpdater(
        **(updater_config or {}), client_config=(client_config or {})
    )
    result = await updater.get(url, force=force_refresh) or b""
    content = result.decode()
    matches = re.findall(
        r"(https:\/\/collector.torproject.org\/recent\/exit-lists\/[0-9]{4}-([0-9]{2}-){4}[0-9]{2})",
        content,
    )

    urls = [url[0] for url in matches]
    urls.sort(reverse=True)
    exit_list = (
        await ResourceUpdater(
            **(updater_config or {}), client_config=(client_config or {})
        ).get(urls[0], force=force_refresh)
        or b""
    )
    exit_nodes = {
        line.split()[1]
        for line in exit_list.decode().splitlines()
        if line.startswith("ExitAddress")
    }
    out = {
        "ipv4": [ip for ip in exit_nodes if is_valid_ipv4(ip)],
        "ipv6": [ip for ip in exit_nodes if is_valid_ipv6(ip)],
    }
    return out
