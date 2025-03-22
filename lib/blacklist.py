import asyncio
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

from loguru import logger

from .models import UpdaterConfig
from .updater import ResourceUpdater
from .utils import (
    extract_cidr_ips,
    extract_ips,
    get_module_dir,
    is_valid_ip,
    is_valid_ipv4,
    is_valid_ipv6,
    load_json,
    load_json_async,
    regex_to_cidr,
    save_json_async,
    sort_ips,
)


async def get_jlang_htaccess(
    url="https://gist.githubusercontent.com/curi0usJack/971385e8334e189d93a6cb4671238b10/raw/13b11edf67f746bdd940ff3f2e9b8dc18f8ad7d4/.htaccess",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    response = await updater.get(url, force=force_refresh) or b""

    htaccess_file = response.decode().split("\n")
    htaccess_file = htaccess_file[11:]

    START = 12
    STOP = 11

    file_groups = {
        "amazon,aws,microsoft,azure": htaccess_file[(22 - START) : (31 - STOP)],
        "amazon,aws": htaccess_file[(32 - START) : (114 - STOP)],
        "forcepoint": htaccess_file[(115 - START) : (119 - STOP)],
        "domaintools": htaccess_file[(120 - START) : (122 - STOP)],
        "zscaler": htaccess_file[(123 - START) : (126 - STOP)],
        "misc": htaccess_file[(127 - START) : (137 - STOP)],
        "virustotal": htaccess_file[(138 - START) : (151 - STOP)],
        "trendmicro": htaccess_file[(152 - START) : (172 - STOP)],
        "bluecoat": htaccess_file[(173 - START) : (177 - STOP)],
        "urlquery": htaccess_file[(178 - START) : (189 - STOP)],
        "palo-alto": htaccess_file[(190 - START) : (207 - STOP)],
        "proofpoint": htaccess_file[(208 - START) : (224 - STOP)],
        "messagelabs": htaccess_file[(225 - START) : (249 - STOP)],
        "fortigate": htaccess_file[(250 - START) : (267 - STOP)],
        "symantec": htaccess_file[(268 - START) : (306 - STOP)],
        "jlang_microsoft": htaccess_file[(307 - START) : (310 - STOP)],
        "microsoft,azure": htaccess_file[(311 - START) : (435 - STOP)],
        "barracuda": htaccess_file[(444 - START) : (447 - STOP)],
        "jlang_tor": htaccess_file[(452 - START) : -1],  # Go until EOF
    }
    out = {}

    for key, value in file_groups.items():
        ips = extract_ips("".join(value))
        out[key] = {
            "ipv4": [ip for ip in ips if is_valid_ipv4(ip)],
            "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
        }

    return out


def process_google_ip_ranges(ip_ranges):
    return {
        re.sub(r"\s+", "_", service.lower()): {
            "ipv4": [
                r["ipv4Prefix"]
                for r in ip_ranges["prefixes"]
                if r["service"].lower() == service.lower() and "ipv4Prefix" in r
            ],
            "ipv6": [
                r["ipv6Prefix"]
                for r in ip_ranges["prefixes"]
                if r["service"].lower() == service.lower() and "ipv6Prefix" in r
            ],
        }
        for service in {r["service"].lower() for r in ip_ranges["prefixes"]}
    }


async def get_google_ips(
    url="https://www.gstatic.com/ipranges/cloud.json",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b"{}"

    ip_ranges: Dict[str, Any] = json.loads(result)
    if not ip_ranges.get("prefixes"):
        logger.warning(f"[!] Retrieved dictionary empty for {url}")
        return {}

    return process_google_ip_ranges(ip_ranges)


def process_aws_ip_ranges(ip_ranges):
    return {
        service.lower(): {
            "ipv4": [
                r["ip_prefix"]
                for r in ip_ranges["prefixes"]
                if r["service"].lower() == service.lower()
            ],
            "ipv6": [
                r["ipv6_prefix"]
                for r in ip_ranges["ipv6_prefixes"]
                if r["service"].lower() == service.lower()
            ],
        }
        for service in {
            r["service"].lower()
            for r in ip_ranges["prefixes"] + ip_ranges["ipv6_prefixes"]
        }
    }


async def get_aws_ips(
    url="https://ip-ranges.amazonaws.com/ip-ranges.json",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b"{}"

    ip_ranges = json.loads(result)

    if not ip_ranges:
        logger.warning(f"[!] Retrieved dictionary empty for {url}")
        return {}

    if not ip_ranges["prefixes"]:
        logger.warning(f"[!] Retrieved dictionary key prefixes missing for {url}")
        return {}

    return process_aws_ip_ranges(ip_ranges)


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


async def get_cloudflare_ips(
    url="https://api.cloudflare.com/client/v4/ips",
    jd_cloud=True,
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
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


async def get_linode_ips(
    url="https://geoip.linode.com/",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""
    ips = [line.split(",")[0] for line in result.decode().splitlines()]
    out = {
        "ipv4": [ip for ip in ips if is_valid_ipv4(ip)],
        "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
    }
    return out


async def get_tor_exit_nodes(
    url: str = "https://metrics.torproject.org/collector/recent/exit-lists/",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""
    content = result.decode()
    matches = re.findall(
        r"(https:\/\/collector.torproject.org\/recent\/exit-lists\/[0-9]{4}-([0-9]{2}-){4}[0-9]{2})",
        content,
    )

    urls = [url[0] for url in matches]
    urls.sort(reverse=True)
    exit_list = (
        await ResourceUpdater(**updater_config, client_config=client_config).get(
            urls[0], force=force_refresh
        )
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


async def get_ipsum_ips(
    url="https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    threshold=3,
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""
    ips = []
    for line in result.decode().splitlines():
        if not line.startswith("#"):
            parts = line.split()
            if len(parts) == 2:
                ip, count_str = parts
                try:
                    count = int(count_str)
                    if count >= threshold:
                        ips.append(ip)
                except ValueError:
                    continue

    out = {
        "ipv4": [ip for ip in ips if is_valid_ipv4(ip)],
        "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
    }
    return out


async def get_github_ips(
    url="https://api.github.com/meta",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b"{}"
    ranges = json.loads(result)

    if not ranges:
        logger.warning(f"[!] Retrieved dictionary empty: {url}")
        return {}

    results = {}
    for service, ip_ranges in ranges.items():
        if not isinstance(ip_ranges, list):
            continue

        service_name: str = service

        if "/" in service_name or "\\" in service_name:
            continue

        out = {
            "ipv4": list([ip for ip in ip_ranges if is_valid_ipv4(ip)]),
            "ipv6": list([ip for ip in ip_ranges if is_valid_ipv6(ip)]),
        }

        if out["ipv4"] or out["ipv6"]:
            results[service_name] = out

    return results


async def get_ipinfo_asn_ranges(
    asn: str,
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    url = f"https://ipinfo.io/{asn}"

    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""

    ips = extract_ips(result.decode())

    return {
        "ipv4": [ip for ip in ips if is_valid_ipv4(ip)],
        "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
    }


async def get_symantec_ranges(
    url="https://knowledge.broadcom.com/external/article/150693/ip-address-ranges-for-email-symantecclou.html",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""

    ips = extract_cidr_ips(result.decode())
    return {
        "ipv4": [ip for ip in ips if is_valid_ipv4(ip)],
        "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
    }


async def get_fortinet_ips(
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    return await get_ipinfo_asn_ranges(
        "AS40934", updater_config, client_config, force_refresh
    )


async def get_paloalto_ips(
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    return await get_ipinfo_asn_ranges(
        "AS54538", updater_config, client_config, force_refresh
    )


async def get_forcepoint_ips(
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    return await get_ipinfo_asn_ranges(
        "AS44444", updater_config, client_config, force_refresh
    )


async def get_digitalocean_ips(
    url="https://www.digitalocean.com/geo/google.csv",
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh) or b""

    ranges = [line.split(",")[0] for line in result.decode().splitlines() if line]

    return {
        "ipv4": [ip for ip in ranges if is_valid_ipv4(ip)],
        "ipv6": [ip for ip in ranges if is_valid_ipv6(ip)],
    }


async def get_zscaler_ips(
    url="https://config.zscaler.com/api/getdata/zscalerthree.net/all/cenr",
    params={"site": "config.zscaler.com"},
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
):
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(url, force=force_refresh, params=params) or b""
    ips = extract_ips(result.decode())

    return {
        "ipv4": sort_ips([ip for ip in ips if is_valid_ipv4(ip)]),
        "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
    }


def get_extra_ranges(
    filename: Optional[str] = None,
) -> Dict[str, Dict[str, List[str]]]:
    script_dir = get_module_dir()
    filename = filename or script_dir / "static" / "extra_ranges.json"
    return load_json(filename)


def get_regex_ranges(
    filename: Optional[str] = None,
) -> Dict[str, Dict[str, List[str]]]:
    script_dir = get_module_dir()
    filename = filename or script_dir / "static" / "regex_ips.txt"

    with open(filename) as fd:
        ips = list(map(regex_to_cidr, fd))
    return {
        "ipv4": sort_ips([ip for ip in ips if is_valid_ipv4(ip)]),
        "ipv6": sort_ips([ip for ip in ips if is_valid_ipv6(ip)]),
    }


def get_spread_ranges(
    filename: Optional[str] = None,
) -> Dict[str, Dict[str, List[str]]]:
    script_dir = get_module_dir()
    filename = filename or script_dir / "static" / "spread.txt"
    with open(filename) as fd:
        ips = extract_ips(fd.read())
    return {
        "ipv4": sort_ips([ip for ip in ips if is_valid_ipv4(ip)]),
        "ipv6": [ip for ip in ips if is_valid_ipv6(ip)],
    }


def get_bl_ranges(
    filename: Optional[str] = None,
) -> Dict[str, Dict[str, List[str]]]:
    script_dir = get_module_dir()
    filename = filename or script_dir / "static" / "bl.txt"
    with open(filename) as fd:
        ips = [line.strip() for line in fd if line.strip()]

    return {
        "ipv4": sort_ips([ip for ip in ips if is_valid_ipv4(ip)]),
        "ipv6": sort_ips([ip for ip in ips if is_valid_ipv6(ip)]),
    }


ASN_SOURCES = {
    "ipv4": {
        "url": "https://raw.githubusercontent.com/molangning/irr-tracker/main/sources/asn_ipv4.json",
        "path": "asn_ipv4.json",
    },
    "ipv6": {
        "url": "https://raw.githubusercontent.com/molangning/irr-tracker/main/sources/asn_ipv6.json",
        "path": "asn_ipv6.json",
    },
}


async def get_github_tree_sha(
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
) -> Dict[str, str]:
    endpoint = (
        "https://api.github.com/repos/molangning/irr-tracker/git/trees/main:sources%2F"
    )

    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(endpoint, force=force_refresh) or b"{}"
    tree = json.loads(result)["tree"]

    return {
        item["path"]: item["sha"]
        for item in tree
        if item["path"] in [src["path"] for src in ASN_SOURCES.values()]
    }


def get_cache_paths(cache_dir: Optional[str] = None) -> Tuple[Path, Path]:
    """Get standardized cache file paths"""
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    return (cache_dir / "history.json", cache_dir / "asn_maps.json")


async def get_asn_maps(
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
) -> Dict[str, Dict[str, Any]]:
    cache_dir = updater_config.get("cache_dir", "")
    history_path, cache_path = get_cache_paths(cache_dir)

    if not force_refresh:
        try:
            with open(history_path) as f:
                history = json.load(f)
            with open(cache_path) as f:
                cached_data = json.load(f)

            tree_shas = await get_github_tree_sha(
                updater_config, client_config, force_refresh
            )
            cache_valid = all(
                history.get(source["path"]) == tree_shas.get(source["path"])
                for source in ASN_SOURCES.values()
            )

            if cache_valid:
                logger.debug("Using cached ASN maps")
                return cached_data

        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.debug(f"Cache load failed: {e}")

    logger.debug("Fetching fresh ASN maps")
    tree_shas = await get_github_tree_sha(updater_config, client_config, force_refresh)

    tasks = [
        ResourceUpdater(**updater_config, client_config=client_config).get(
            source["url"], force=force_refresh
        )
        for source in ASN_SOURCES.values()
    ]

    results_raw = await asyncio.gather(*tasks, return_exceptions=True)

    results = {}
    for (ip_ver, source), result in zip(ASN_SOURCES.items(), results_raw):
        if isinstance(result, Exception):
            logger.error(f"Failed to fetch {source['url']}: {result}")
        else:
            results[ip_ver] = json.loads(result.decode())

    history = {
        source["path"]: tree_shas.get(source["path"]) for source in ASN_SOURCES.values()
    }

    try:
        file_save_tasks = [
            save_json_async(json_data, json_path)
            for json_data, json_path in zip(
                [history, results], [history_path, cache_path]
            )
        ]
        await asyncio.gather(*file_save_tasks)
        logger.debug("Cached ASN maps updated")
    except OSError as e:
        logger.warning(f"Failed to save cache: {e}")

    return results


async def get_asn_maps2(
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
) -> Dict[str, Dict[str, Any]]:
    history_path, cache_path = get_cache_paths()

    if not force_refresh:
        try:
            with open(history_path) as f:
                history = json.load(f)
            with open(cache_path) as f:
                cached_data = json.load(f)

            tree_shas = await get_github_tree_sha(
                updater_config, client_config, force_refresh
            )
            cache_valid = all(
                history.get(source["path"]) == tree_shas.get(source["path"])
                for source in ASN_SOURCES.values()
            )

            if cache_valid:
                logger.debug("Using cached ASN maps")
                return cached_data

        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.debug(f"Cache load failed: {e}")

    logger.debug("Fetching fresh ASN maps")
    tree_shas = await get_github_tree_sha(updater_config, client_config, force_refresh)
    results = {}

    for ip_ver, source in ASN_SOURCES.items():
        result = (
            await ResourceUpdater(**updater_config, client_config=client_config).get(
                source["url"], force=force_refresh
            )
            or b""
        )
        results[ip_ver] = json.loads(result.decode())

    history = {
        source["path"]: tree_shas.get(source["path"]) for source in ASN_SOURCES.values()
    }

    try:
        await save_json_async(history, history_path)
        await save_json_async(results, cache_path)
        logger.debug("cached ASN maps updated")
    except OSError as e:
        logger.warning(f"Failed to save cache: {e}")

    return results


def get_asn_ranges(
    asn: str, asn_ipv4_map: Dict, asn_ipv6_map: Dict
) -> Dict[str, List[str]]:
    if not asn.startswith("AS"):
        asn = "AS" + asn

    return {"ipv4": asn_ipv4_map.get(asn, []), "ipv6": asn_ipv6_map.get(asn, [])}


async def get_asn_list_by_tag(
    tag,
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
) -> List[str]:
    api_endpoint = "https://bgp.tools/tags/%s.txt"
    updater = ResourceUpdater(**updater_config, client_config=client_config)
    result = await updater.get(api_endpoint % (tag), force=force_refresh) or b""
    return result.decode().splitlines()


async def get_tag_ip_ranges(
    tag: str,
    asn_maps: Optional[Dict[str, Dict]] = None,
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
) -> Dict[str, List[str]]:
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
    tags: List[str] = ["vpn", "tor"],
    asn_maps: Optional[Dict[str, Dict]] = None,
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
) -> Dict[str, Dict[str, List[str]]]:
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


async def get_vpn_ip_ranges(
    asn_maps: Optional[Dict[str, Dict]] = None,
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
) -> Dict[str, List[str]]:
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
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
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


async def get_asn_ranges_by_name(
    match_conditions: Optional[Dict[str, Dict[str, List[str]]]] = None,
    url: str = "https://ftp.ripe.net/ripe/asnames/asn.txt",
    asn_maps: Optional[Dict[str, Dict]] = None,
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
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


async def get_all_ranges(
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
    *,
    config: Dict[str, Any] = {},
) -> Dict[str, Dict[str, List[str]]]:
    results = {}

    default_updater_config = UpdaterConfig.model_validate(
        config.get("updater", updater_config)
    )
    sources_updater_config: Dict[str, Any] = config.get("sources", {})

    tasks = []

    for source_name, get_function in [
        ("asn", get_asn_ranges_by_name),
        ("aws", get_aws_ips),
        ("azure", get_azure_ips),
        ("blocklist_de", get_blocklist_de),
        ("cloudflare", get_cloudflare_ips),
        ("digitalocean", get_digitalocean_ips),
        ("forcepoint", get_forcepoint_ips),
        ("fortinet", get_fortinet_ips),
        ("github", get_github_ips),
        ("google", get_google_ips),
        ("ipsum", get_ipsum_ips),
        ("isc", get_isc_thread_category),
        ("jlang", get_jlang_htaccess),
        ("linode", get_linode_ips),
        ("microsoft", get_microsoft_public_ips),
        ("microsoft_eop", get_microsoft_eop_ranges),
        ("msft_tracker", get_microsoft_ip_tracker_ranges),
        ("others", get_other_asn_ranges),
        ("paloalto", get_paloalto_ips),
        ("symantec", get_symantec_ranges),
        ("tor_exit_nodes", get_tor_exit_nodes),
        ("tags", get_multiple_tag_ranges),
        ("zscaler", get_zscaler_ips),
    ]:
        source_updater_config = UpdaterConfig.model_validate(
            sources_updater_config.get(source_name, {})
        )

        updater_config = default_updater_config.model_copy(
            update=source_updater_config.model_dump(exclude_unset=True)
        )

        global_force_refresh = config.get("general", {}).get(
            "force_refresh", force_refresh
        )
        source_force_refresh = sources_updater_config.get(source_name, {}).get(
            "force_refresh"
        )
        force_refresh = source_force_refresh or global_force_refresh

        logger.debug(
            f"{source_name} force refresh: {force_refresh}, ttl: {updater_config.cache_ttl}"
        )

        tasks.append(
            (
                source_name,
                get_function(
                    updater_config=updater_config.model_dump(),
                    client_config=client_config,
                    force_refresh=force_refresh,
                ),
            )
        )

    completed = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)

    for name, result in zip([t[0] for t in tasks], completed):
        if isinstance(result, Exception):
            logger.error(f"Error fetching {name}: {result}")
            results[name] = {"ipv4": [], "ipv6": []}
        else:
            results[name] = result

    results["extras"] = get_extra_ranges()
    results["spread"] = get_spread_ranges()
    results["regex"] = get_regex_ranges()
    results["bl"] = get_bl_ranges()

    return results


async def get_all_rangesv0(
    updater_config: Optional[Dict[str, Any]] = {},
    client_config: Optional[Dict[str, Any]] = {},
    force_refresh: bool = False,
) -> Dict[str, Dict[str, List[str]]]:
    results = {}

    tasks = [
        (
            "asn",
            get_asn_ranges_by_name(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "aws",
            get_aws_ips(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "azure",
            get_azure_ips(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "blocklist_de",
            get_blocklist_de(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "cloudflare",
            get_cloudflare_ips(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "digitalocean",
            get_digitalocean_ips(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "forcepoint",
            get_forcepoint_ips(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "fortinet",
            get_fortinet_ips(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "github",
            get_github_ips(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "google",
            get_google_ips(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "ipsum",
            get_ipsum_ips(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "isc",
            get_isc_thread_category(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "jlang",
            get_jlang_htaccess(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "linode",
            get_linode_ips(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "microsoft",
            get_microsoft_public_ips(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "microsoft_eop",
            get_microsoft_eop_ranges(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "others",
            get_other_asn_ranges(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "paloalto",
            get_paloalto_ips(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "symantec",
            get_symantec_ranges(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "tor_exit_nodes",
            get_tor_exit_nodes(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "tags",
            get_multiple_tag_ranges(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
        (
            "zscaler",
            get_zscaler_ips(
                updater_config=updater_config,
                client_config=client_config,
                force_refresh=force_refresh,
            ),
        ),
    ]

    completed = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)

    for name, result in zip([t[0] for t in tasks], completed):
        if isinstance(result, Exception):
            logger.error(f"Error fetching {name}: {result}")
            results[name] = {"ipv4": [], "ipv6": []}
        else:
            results[name] = result

    results["extras"] = get_extra_ranges()
    results["spread"] = get_spread_ranges()
    results["regex"] = get_regex_ranges()
    results["bl"] = get_bl_ranges()

    return results


async def get_redirect_rules(config: dict) -> dict:
    try:
        redirect_dir = config["static_dir"]

        files = {
            "msft_remote_hosts": "msft_remote_hosts.json",
            "aggressive_remote_hosts": "aggressive_remote_hosts.json",
            "other_remote_hosts": "other_remote_hosts.json",
            "user_agents": "user_agents.json",
            "redirect_domains": "redirect_domains.json",
        }

        tasks = [
            load_json_async(str(Path(redirect_dir) / filename))
            for filename in files.values()
        ]
        loaded = await asyncio.gather(*tasks, return_exceptions=True)

        results = {}
        for key, result in zip(files.keys(), loaded):
            if isinstance(result, Exception):
                logger.error(f"Failed to load {key}: {result}")

            else:
                results[key] = result

        remote_hosts = sorted(
            results.get("msft_remote_hosts", [])
            + results.get("aggressive_remote_hosts", [])
            + results.get("other_remote_hosts", [])
        )

        processed_domains = []
        for domain in results.get("redirect_domains", []):
            if isinstance(domain, str):
                if not domain.startswith("https://"):
                    processed_domains.append(f"https://{domain}")
                else:
                    processed_domains.append(domain)
            else:
                logger.warning(f"Skipping invalid domain: {domain}")

        return {
            "user_agents": results.get("user_agents", []),
            "remote_hosts": remote_hosts,
            "redirect_domains": sorted(processed_domains),
        }

    except Exception as e:
        logger.error(f"Error in redirect rules processing: {e}")
        raise


SOURCE_TO_GETTER_MAP = {
    "asn_map": get_asn_maps,
    "asn": get_asn_ranges_by_name,
    "aws": get_aws_ips,
    "azure": get_azure_ips,
    "blocklist_de": get_blocklist_de,
    "cloudflare": get_cloudflare_ips,
    "digitalocean": get_digitalocean_ips,
    "forcepoint": get_forcepoint_ips,
    "fortinet": get_fortinet_ips,
    "github": get_github_ips,
    "google": get_google_ips,
    "ipsum": get_ipsum_ips,
    "isc": get_isc_thread_category,
    "jlang": get_jlang_htaccess,
    "linode": get_linode_ips,
    "microsoft": get_microsoft_public_ips,
    "microsoft_eop": get_microsoft_eop_ranges,
    "others": get_other_asn_ranges,
    "paloalto": get_paloalto_ips,
    "symantec": get_symantec_ranges,
    "tor_exit_nodes": get_tor_exit_nodes,
    "tags": get_multiple_tag_ranges,
    "zscaler": get_zscaler_ips,
    "msft_tracker": get_microsoft_ip_tracker_ranges,
}
