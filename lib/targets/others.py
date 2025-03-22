from typing import Any, Dict, List, Optional
import asyncio

from loguru import logger

from ..updater import ResourceUpdater
from .asn_maps import get_asn_maps, get_asn_ranges
from ..utils import get_module_dir, is_valid_ipv4, is_valid_ipv6, load_json
import json


async def fetch_asn_ranges(
    asn: str,
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
) -> List[str]:
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"

    ranges: List[str] = []

    try:
        updater = ResourceUpdater(**updater_config, client_config=client_config)
        result = await updater.get(url, force=force_refresh) or b"{}"

        data: Dict[str, Any] = json.loads(result)

        if data.get("status") == "ok":
            prefixes = data.get("data", {}).get("prefixes", [])
            ranges.extend(
                prefix["prefix"] for prefix in prefixes if prefix.get("prefix")
            )
        else:
            logger.warning(f"Error fetching AS{asn}: {data.get('status_message')}")

    except Exception as e:
        logger.error(f"Failed to fetch data for AS{asn}: {str(e)}")

    return ranges


async def get_other_asn_ranges(
    filename: Optional[str] = None,
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
) -> Dict[str, List[str]]:
    filename = filename or get_module_dir() / "static" / "other_asns.txt"
    with open(filename) as fd:
        other_asns = [line.strip() for line in fd if line.strip()]

    tasks = [
        fetch_asn_ranges(asn, updater_config, client_config, force_refresh)
        for asn in other_asns
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    ipv4_ranges: List[str] = []
    ipv6_ranges: List[str] = []
    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Error fetching ASN ranges: {result}")
        else:
            ipv4_ranges.extend([ip for ip in result if is_valid_ipv4(ip)])
            ipv6_ranges.extend([ip for ip in result if is_valid_ipv6(ip)])

    return {
        "ipv4": ipv4_ranges,
        "ipv6": ipv6_ranges,
    }
