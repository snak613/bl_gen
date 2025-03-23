import asyncio
from typing import Any, Dict, List, Optional

from loguru import logger

from ..updater import ResourceUpdater
from ..utils import get_module_dir, load_json
from .asn_maps import get_asn_maps, get_asn_ranges


async def get_asn_list_by_tag(
    tag,
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
) -> List[str]:
    updater_config = updater_config or {}
    api_endpoint = "https://bgp.tools/tags/%s.txt"
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(api_endpoint % (tag), force=force_refresh) or b""
    return result.decode().splitlines()


async def get_tag_ip_ranges(
    tag: str,
    asn_maps: Optional[Dict[str, Dict]] = None,
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
) -> Dict[str, List[str]]:
    updater_config = updater_config or {}
    if asn_maps is None:
        asn_maps = await get_asn_maps(updater_config, client_config, force_refresh)

    asn_list = await get_asn_list_by_tag(
        tag, updater_config, client_config, force_refresh
    )
    logger.debug(f"{tag}: Got {len(asn_list)} ASNs")

    ipv4_ranges: List[str] = []
    ipv6_ranges: List[str] = []

    asns_with_ranges = 0
    for asn in asn_list:
        ranges = get_asn_ranges(asn, asn_maps.get("ipv4", {}), asn_maps.get("ipv6", {}))
        if ranges["ipv4"] or ranges["ipv6"]:
            asns_with_ranges += 1
        ipv4_ranges.extend(ranges["ipv4"])
        ipv6_ranges.extend(ranges["ipv6"])

    logger.debug(f"{tag}: {asns_with_ranges}/{len(asn_list)} ASNs had ranges")
    logger.debug(
        f"{tag}: Found {len(ipv4_ranges)} IPv4 and {len(ipv6_ranges)} IPv6 ranges"
    )

    return {"ipv4": ipv4_ranges, "ipv6": ipv6_ranges}


async def get_multiple_tag_ranges(
    tags: Optional[List[str]] = None,
    asn_maps: Optional[Dict[str, Dict]] = None,
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
) -> Dict[str, Dict[str, List[str]]]:
    tags = tags or ["vpn", "tor"]
    updater_config = updater_config or {}
    if asn_maps is None:
        asn_maps = await get_asn_maps(updater_config, client_config, force_refresh)
        logger.debug(
            f"ASN Maps contain: IPv4={len(asn_maps.get('ipv4', {}))} ASNs, IPv6={len(asn_maps.get('ipv6', {}))} ASNs"
        )

    tasks = [
        get_tag_ip_ranges(tag, asn_maps, updater_config, client_config, force_refresh)
        for tag in tags
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    processed_results = {}

    for tag, result in zip(tags, results):
        if isinstance(result, Exception):
            logger.error(f"Failed to fetch {tag} IP ranges: {result}")
        else:
            processed_results[tag] = result

    return processed_results


async def get_asn_ranges_by_name(
    match_conditions: Optional[Dict[str, Dict[str, List[str]]]] = None,
    url: str = "https://ftp.ripe.net/ripe/asnames/asn.txt",
    asn_maps: Optional[Dict[str, Dict]] = None,
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
) -> Dict[str, Dict[str, List[str]]]:
    if asn_maps is None:
        asn_maps = await get_asn_maps(updater_config, client_config, force_refresh)

    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""
    asn_entries = []

    for line in result.decode().splitlines():
        if not line:
            continue
        try:
            asn, remainder = line.split(" ", 1)
            if "reserved by" in remainder:
                name, country = remainder, "zz"
            else:
                name, country = remainder.rsplit(", ", 1)
            asn_entries.append((asn, name.lower(), country))
        except ValueError:
            continue

    logger.debug(f"Loaded {len(asn_entries)} ASN entries")

    def matches_criteria(name: str, criteria: Dict[str, List[str]]) -> bool:
        for reject in criteria.get("reject", []):
            if reject.lower() in name:
                return False
        return any(match.lower() in name for match in criteria.get("match", []))

    results = {}
    if not match_conditions:
        filepath = get_module_dir() / "static" / "asn_list.json"
        match_conditions = load_json(filepath)

    for category, criteria in match_conditions.items():
        if "/" in category or "\\" in category:  # Security check
            continue

        matching_asns = [
            entry[0] for entry in asn_entries if matches_criteria(entry[1], criteria)
        ]

        if not matching_asns:
            logger.debug(f"No matching ASNs found for {category}")
            continue

        logger.debug(f"{category}: Found {len(matching_asns)} matching ASNs")

        ipv4_ranges: List[str] = []
        ipv6_ranges: List[str] = []

        for asn in matching_asns:
            ranges = get_asn_ranges(
                asn, asn_maps.get("ipv4", {}), asn_maps.get("ipv6", {})
            )
            ipv4_ranges.extend(ranges["ipv4"])
            ipv6_ranges.extend(ranges["ipv6"])

        results[category] = {
            "ipv4": ipv4_ranges,
            "ipv6": ipv6_ranges,
        }

        logger.debug(
            f"{category}: Collected {len(ipv4_ranges)} IPv4 and {len(ipv6_ranges)} IPv6 ranges"
        )

    return results


async def get_vpn_ip_ranges(
    asn_maps: Optional[Dict[str, Dict]] = None,
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
) -> Dict[str, List[str]]:
    updater_config = updater_config or {}
    if asn_maps is None:
        asn_maps = await get_asn_maps(updater_config, client_config, force_refresh)
        logger.debug(
            f"ASN Maps contain: IPv4={len(asn_maps.get('ipv4', {}))} ASNs, IPv6={len(asn_maps.get('ipv6', {}))} ASNs"
        )
    return await get_tag_ip_ranges(
        "vpn", asn_maps, updater_config, client_config, force_refresh
    )


async def get_tor_ip_ranges(
    asn_maps: Optional[Dict[str, Dict]] = None,
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
) -> Dict[str, List[str]]:
    if asn_maps is None:
        asn_maps = await get_asn_maps(updater_config, client_config, force_refresh)
        logger.debug(
            f"ASN Maps contain: IPv4={len(asn_maps.get('ipv4', {}))} ASNs, IPv6={len(asn_maps.get('ipv6', {}))} ASNs"
        )
    return await get_tag_ip_ranges(
        "tor", asn_maps, updater_config, client_config, force_refresh
    )
