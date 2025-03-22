import json
from typing import Any, Dict, Optional


from ..updater import ResourceUpdater

from loguru import logger
import asyncio
from pathlib import Path
from typing import Tuple, List


from ..utils import save_json_async


def get_cache_paths(cache_dir: Optional[str] = None) -> Tuple[Path, Path]:
    """Get standardized cache file paths"""
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    return (cache_dir / "history.json", cache_dir / "asn_maps.json")


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
