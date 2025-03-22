from ..updater import ResourceUpdater
import re
from typing import Any, Dict, Optional

from loguru import logger
from ..utils import is_valid_ipv4, is_valid_ipv6
import json


async def get_azure_ips(
    url="https://www.microsoft.com/en-us/download/details.aspx?id=56519",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""

    download_url = re.findall(
        r"https:\/\/download.microsoft.com\/download\/.*?\.json", result.decode()
    )[0]

    if not download_url:
        raise ValueError("Could not find Azure IP ranges download URL")

    azure_ips = (
        await ResourceUpdater(**updater_config, client_config=client_config).get(
            download_url, force=force_refresh
        )
        or b"{}"
    )
    azure_ips = json.loads(azure_ips).get("values", [])

    if not azure_ips:
        logger.warning(f"[!] Retrieved empty for {url}")

    results = {}

    for range_data in azure_ips:
        service_name = range_data["name"].lower()
        ip_ranges = range_data["properties"]["addressPrefixes"]
        ipv4 = [ip for ip in ip_ranges if is_valid_ipv4(ip)]
        ipv6 = [ip for ip in ip_ranges if is_valid_ipv6(ip)]
        out = {"ipv4": ipv4, "ipv6": ipv6}
        if out["ipv4"] or out["ipv6"]:
            results[service_name] = out
    return results


async def get_microsoft_public_ips(
    url="https://download.microsoft.com/download/B/2/A/B2AB28E1-DAE1-44E8-A867-4987FE089EBE/msft-public-ips.csv",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    try:
        updater = ResourceUpdater(**updater_config, client_config=client_config)
        result = await updater.get(url, force=force_refresh) or b""
        if "404 Not Found" in result.decode():
            logger.error("Microsoft IPs URL is no longer valid - needs updating")
            return {"ipv4": [], "ipv6": []}

        lines = result.decode().splitlines()
        if not lines:
            return {"ipv4": [], "ipv6": []}

        ranges = [line.split(",")[0] for line in lines[1:]]

        return {
            "ipv4": [ip for ip in ranges if is_valid_ipv4(ip)],
            "ipv6": [ip for ip in ranges if is_valid_ipv6(ip)],
        }

    except Exception as e:
        logger.error(f"Error fetching Microsoft public IPs: {e}")
        return {"ipv4": [], "ipv6": []}


async def get_microsoft_eop_ranges(
    url="https://endpoints.office.com/endpoints/worldwide",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    import uuid

    params = {"clientrequestid": str(uuid.uuid4())}
    try:
        updater = ResourceUpdater(**updater_config, client_config=client_config)
        result = await updater.get(url, force=force_refresh, params=params) or b"[]"
        result = json.loads(result)
        ranges = []
        for data in result:
            ranges.extend(data.get("ips", []))

        return {
            "ipv4": [ip for ip in ranges if is_valid_ipv4(ip)],
            "ipv6": [ip for ip in ranges if is_valid_ipv6(ip)],
        }

    except Exception as e:
        logger.error(f"Error fetching Microsoft Endpoint Office Protection IPs: {e}")
        return {"ipv4": [], "ipv6": []}


async def get_microsoft_ip_tracker_ranges(
    url: Optional[str] = None,
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    url = url or (
        "https://github.com/aalex954/MSFT-IP-Tracker"
        "/releases/latest/download/msft_asn_ip_ranges.txt"
    )

    try:
        updater = ResourceUpdater(**updater_config, client_config=client_config)
        result = await updater.get(url, force=force_refresh) or b""
        ranges = result.decode().splitlines()

        return {
            "ipv4": [ip for ip in ranges if is_valid_ipv4(ip)],
            "ipv6": [ip for ip in ranges if is_valid_ipv6(ip)],
        }

    except Exception as e:
        logger.error(f"Error fetching Microsoft Tracker from Alex954's Github: {e}")
        return {"ipv4": [], "ipv6": []}
