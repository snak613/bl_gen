from typing import Any, Dict, Optional
from .ipinfo import get_ipinfo_asn_ranges


async def get_paloalto_ips(
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    return await get_ipinfo_asn_ranges(
        "AS54538", updater_config, client_config, force_refresh
    )
