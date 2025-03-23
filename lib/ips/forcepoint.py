from typing import Any, Dict, Optional

from .ipinfo import get_ipinfo_asn_ranges


async def get_forcepoint_ips(
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
):
    updater_config = updater_config or {}
    return await get_ipinfo_asn_ranges(
        "AS44444", updater_config, client_config, force_refresh
    )
