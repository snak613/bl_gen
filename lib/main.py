import asyncio
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import aiofiles
from aggregate_prefixes import aggregate_prefixes
from loguru import logger

from .blacklist import get_all_ranges, get_cloudflare_ips
from .utils import get_module_dir, save_json_async, sort_ips

STATIC_DIR = get_module_dir() / "static" / "blacklist"

SERVICE_GROUPS = {
    "google",
    "aws",
    "azure",
    "cloudflare",
}
ALWAYS_FLATTEN = ["asn", "isc", "blocklist_de", "tags", "extras", "jlang"]


class IPManager:
    def __init__(
        self,
        *,
        always_flatten: List[str] = None,
        flatten_service_groups: bool = False,
        service_groups: Optional[Set[str]] = None,
        client_options: Dict[str, Any] = None,
        updater_config: Dict[str, Any] = None,
        config: Dict[str, Any] = None,
    ):
        self.service_groups = service_groups or SERVICE_GROUPS
        self.always_flatten = always_flatten or ALWAYS_FLATTEN.copy()
        self.flatten_service_groups = flatten_service_groups
        self.client_options = client_options or {}
        self.updater_config = updater_config or {}
        self.config = config or {}

        self._processed_data: Dict[str, Dict[str, List[str]]] = {}
        self._raw_data: Dict[str, Any] = {}

    async def initialize(self, force_refresh: bool = False):
        self._raw_data = await get_all_ranges(
            updater_config=self.updater_config,
            client_config=self.client_options,
            force_refresh=force_refresh,
            config=self.config,
        )
        self._process_data()
        logger.info(f"Initialized with {len(self._raw_data)} data sources")

    def _process_data(self):
        processed = defaultdict(lambda: {"ipv4": set(), "ipv6": set()})

        for source, data in self._raw_data.items():
            if not isinstance(data, dict):
                logger.warning(f"Data is of type : {type(data)} please check")
                continue

            if source in self.always_flatten:
                self._process_flattened_source(source, data, processed)
            elif source in self.service_groups:
                self._process_service_group(source, data, processed)
            else:
                self._process_generic_source(source, data, processed)

        self._processed_data = {
            group: {
                "ipv4": sort_ips(list(ranges["ipv4"])),
                "ipv6": sort_ips(list(ranges["ipv6"])),
            }
            for group, ranges in processed.items()
            if ranges["ipv4"] or ranges["ipv6"]
        }

    def _process_flattened_source(self, source: str, data: Dict, processed: Dict):
        """Process sources that should always be flattened"""
        flattened = self._flatten_nested_data(data)
        for group, ranges in flattened.items():
            processed[group]["ipv4"].update(ranges.get("ipv4", []))
            processed[group]["ipv6"].update(ranges.get("ipv6", []))

    def _process_service_group(self, source: str, data: Dict, processed: Dict):
        """Process service group data with optional flattening"""
        if self.flatten_service_groups:
            flattened = self._flatten_nested_data(data, source)
            processed.update(flattened)
        else:
            for _, subdata in data.items():
                if isinstance(subdata, dict):
                    processed[source]["ipv4"].update(subdata.get("ipv4", []))
                    processed[source]["ipv6"].update(subdata.get("ipv6", []))

    def _process_generic_source(self, source: str, data: Dict, processed: Dict):
        """Process standard data sources"""
        if "ipv4" in data or "ipv6" in data:
            processed[source]["ipv4"].update(data.get("ipv4", []))
            processed[source]["ipv6"].update(data.get("ipv6", []))
        else:
            for _, subdata in data.items():
                if isinstance(subdata, dict):
                    processed[source]["ipv4"].update(subdata.get("ipv4", []))
                    processed[source]["ipv6"].update(subdata.get("ipv6", []))

    def _flatten_nested_data(self, data: Dict, parent_prefix: str = "") -> Dict:
        """Recursively flatten nested data structures"""
        flattened = {}
        for key, value in data.items():
            if not isinstance(value, dict):
                continue

            if "ipv4" in value or "ipv6" in value:
                group_name = f"{parent_prefix}_{key}".lstrip("_")
                flattened[group_name] = {
                    "ipv4": set(value.get("ipv4", [])),
                    "ipv6": set(value.get("ipv6", [])),
                }
            else:
                nested = self._flatten_nested_data(value, f"{parent_prefix}_{key}")
                flattened.update(nested)
        return flattened

    def get_ranges(
        self,
        exclude_groups: Optional[List[str]] = None,
        exclude_ips: Optional[List[str]] = None,
        include_only: Optional[List[str]] = None,
        aggregate: bool = True,
    ) -> Dict[str, List[str]]:
        filter_params = {
            "exclude_groups": set(exclude_groups or []),
            "exclude_ips": set(exclude_ips or []),
            "include_only": set(include_only or []),
        }

        filtered = self._filter_ranges(**filter_params)

        return self._finalize_ranges(filtered, aggregate)

    def _filter_ranges(
        self, exclude_groups: Set[str], exclude_ips: Set[str], include_only: Set[str]
    ) -> Dict:
        """Apply filtering to the processed data"""
        result = {"ipv4": set(), "ipv6": set()}

        for group, ranges in self._processed_data.items():
            if self._should_skip_group(group, exclude_groups, include_only):
                continue

            for version in ["ipv4", "ipv6"]:
                result[version].update(
                    ip for ip in ranges.get(version, []) if ip not in exclude_ips
                )

        return result

    def _should_skip_group(
        self, group: str, exclude_groups: Set[str], include_only: Set[str]
    ) -> bool:
        """Determine if a group should be skipped based on filters"""
        if exclude_groups and group in exclude_groups:
            logger.info(f"Excluding group: {group}")
            return True
        if include_only and group not in include_only:
            return True
        return False

    def _finalize_ranges(self, filtered: Dict, aggregate: bool) -> Dict:
        """Final processing of filtered ranges"""
        ipv4 = filtered["ipv4"]
        ipv6 = filtered["ipv6"]

        logger.info(f"Found {len(ipv4)} IPv4 and {len(ipv6)} IPv6 addresses")

        return {
            "ipv4": self._process_version(ipv4, True, aggregate),
            "ipv6": self._process_version(ipv6, False, aggregate),
        }

    def _process_version(
        self, ips: Set[str], is_v4: bool, aggregate: bool
    ) -> List[str]:
        """Process a single IP version"""
        if not ips:
            return []

        if aggregate:
            aggregated = self._aggregate_ips(list(ips), is_v4)
            version = "ipv4" if is_v4 else "ipv6"
            logger.info(f"Aggregated to {len(aggregated)} {version} prefixes")
            return aggregated

        return sort_ips(list(ips))

    def _aggregate_ips(self, ips: List[str], is_v4: bool) -> List[str]:
        """Aggregate IP addresses with mask handling"""
        aggregated = aggregate_prefixes(ips)
        mask = "/32" if is_v4 else "/128"
        return [
            str(ip).replace(mask, "") if str(ip).endswith(mask) else str(ip)
            for ip in aggregated
        ]

    @property
    def group_info(self) -> Dict[str, Dict[str, int]]:
        """Get summary information about all groups"""
        return {
            group: {
                "ipv4_count": len(ranges["ipv4"]),
                "ipv6_count": len(ranges["ipv6"]),
            }
            for group, ranges in self._processed_data.items()
        }

    @property
    def available_groups(self) -> List[str]:
        """Get sorted list of available group names"""
        return sorted(self._processed_data.keys())


class IPManagerV0:
    def __init__(
        self,
        always_flatten: List[str] = [],
        flatten_service_groups: bool = False,
        service_groups: Optional[Set[str]] = None,
        client_options: Dict[str, Any] = None,
        updater_config: Dict[str, Any] = None,
    ):
        self.service_groups = service_groups or SERVICE_GROUPS
        self.always_flatten = always_flatten or ALWAYS_FLATTEN.copy()
        self.flatten_service_groups = flatten_service_groups
        self.client_options = client_options or {}
        self.updater_config = updater_config or {}

        self._processed_data: Dict[str, Dict[str, List[str]]] = {}
        self._raw_data: Dict[str, Any] = {}

    async def initialize(self, force_refresh: bool = False):
        self._raw_data = await get_all_ranges(
            updater_config=self.updater_config,
            client_config=self.client_options,
            force_refresh=force_refresh,
        )
        self._processed_data = self._process_data()
        logger.info(f"Initialized with {len(self._raw_data)} data sources")

    def _merge_ip_lists(self, lists: List[List[str]]) -> List[str]:
        combined = set()
        for lst in lists:
            combined.update(lst)
        return sort_ips(list(combined))

    def _flatten_nested_data(
        self, data: Dict[str, Dict], parent_prefix: str = ""
    ) -> Dict[str, Dict[str, List[str]]]:
        flattened = {}

        for key, value in data.items():
            if not isinstance(value, dict):
                continue

            if "ipv4" in value or "ipv6" in value:
                group_name = f"{parent_prefix}_{key}".lstrip("_")
                flattened[group_name] = {
                    "ipv4": value.get("ipv4", []),
                    "ipv6": value.get("ipv6", []),
                }
            else:
                nested = self._flatten_nested_data(value, key)
                flattened.update(nested)

        return flattened

    def _aggregate_ips(self, ips: List[str], is_v4: bool = True) -> List[str]:
        if not ips:
            return []

        aggregated = aggregate_prefixes(ips)
        mask = "/32" if is_v4 else "/128"
        return [
            str(ip).replace(mask, "") if str(ip).endswith(mask) else str(ip)
            for ip in aggregated
        ]

    def _process_data(self) -> Dict[str, Dict[str, List[str]]]:
        logger.info("Processing IP range data...")
        processed = defaultdict(lambda: {"ipv4": [], "ipv6": []})

        for source, data in self._raw_data.items():
            if not isinstance(data, dict):
                continue

            if source in self.always_flatten:
                logger.info(f"Flattening {source} data")
                flattened = self._flatten_nested_data(data)
                for group, ranges in flattened.items():
                    for version in ("ipv4", "ipv6"):
                        processed[group][version].extend(ranges.get(version, []))

            elif source in self.service_groups:
                if self.flatten_service_groups:
                    logger.debug(f"Flattening {source} services")
                    flattened = self._flatten_nested_data(data, source)
                    processed.update(flattened)
                else:
                    logger.debug(f"Keeping {source} services grouped")

                    for subgroup_data in data.values():
                        if isinstance(subgroup_data, dict):
                            for version in ("ipv4", "ipv6"):
                                processed[source][version].extend(
                                    subgroup_data.get(version, [])
                                )

            else:
                # Handle both direct and nested structures
                if "ipv4" in data or "ipv6" in data:
                    # Direct ipv4/ipv6 structure
                    for version in ("ipv4", "ipv6"):
                        processed[source][version].extend(data.get(version, []))
                else:
                    for _, subgroup_data in data.items():
                        if isinstance(subgroup_data, dict):
                            if "ipv4" in subgroup_data or "ipv6" in subgroup_data:
                                for version in ("ipv4", "ipv6"):
                                    processed[source][version].extend(
                                        subgroup_data.get(version, [])
                                    )

        final_processed = {}
        for group, ranges in processed.items():
            if ranges["ipv4"] or ranges["ipv6"]:
                final_processed[group] = {
                    "ipv4": sort_ips(list(set(ranges["ipv4"]))),
                    "ipv6": sort_ips(list(set(ranges["ipv6"]))),
                }

        logger.info(
            f"Processed {len(self._raw_data)} sources into {len(final_processed)} groups"
        )
        return final_processed

    def get_ranges(
        self,
        exclude_groups: Optional[List[str]] = None,
        exclude_ips: Optional[List[str]] = None,
        include_only: Optional[List[str]] = None,
        aggregate: bool = True,
    ) -> Dict[str, List[str]]:
        """
        Get IP ranges with exclusions and inclusions applied

        Args:
            exclude_groups: List of group names to exclude
            exclude_ips: List of specific IPs to exclude
            include_only: List of groups to include (excludes all others)
        """
        exclude_groups = set(exclude_groups or [])
        exclude_ips = set(exclude_ips or [])
        include_only = set(include_only or [])

        result = {"ipv4": set(), "ipv6": set()}

        for group, ranges in self._processed_data.items():
            if exclude_groups and group in exclude_groups:
                logger.info(f"Excluding group: {group}")
                continue

            if include_only and group not in include_only:
                continue

            for version in ("ipv4", "ipv6"):
                if version in ranges:
                    result[version].update(
                        ip for ip in ranges[version] if ip not in exclude_ips
                    )

        logger.info(
            f"Found {len(result.get('ipv4', []))} IPv4 and {len(result.get('ipv6', []))} IPv6 addresses"
        )

        if aggregate:
            ipv4_ranges = self._aggregate_ips(list(result["ipv4"]), is_v4=True)
            ipv6_ranges = self._aggregate_ips(list(result["ipv6"]), is_v4=False)
            logger.info(
                f"After aggregation {len(ipv4_ranges)} IPv4 and {len(ipv6_ranges)} IPv6 addresses"
            )

        else:
            ipv4_ranges = sort_ips(list(result["ipv4"]))
            ipv6_ranges = sort_ips(list(result["ipv6"]))

        return {"ipv4": ipv4_ranges, "ipv6": ipv6_ranges}

    def get_group_info(self) -> Dict[str, Dict[str, int]]:
        info = {}
        for group, ranges in self.processed_data.items():
            info[group] = {
                "ipv4_count": len(ranges.get("ipv4", [])),
                "ipv6_count": len(ranges.get("ipv6", [])),
            }
        return info

    def get_available_groups(self) -> List[str]:
        return sorted(list(self.processed_data.keys()))


class RedirectRulesManager:
    def __init__(self, config: Dict[str, Any], persist: bool = True):
        self.config = config
        self.static_dir = STATIC_DIR  ##Path(self.config["static_dir"])

        self.remote_hosts: Dict[str, List[str]] = {
            "msft": [],
            "aggressive": [],
            "others": [],
            "custom": [],
        }
        self.user_agents: List[str] = []
        self.redirect_domains: List[str] = []

        self._configure_paths()

        self.persist_dir = self.config.get("redirect_rules", {}).get("persist_dir")
        if persist:
            self._init_persistence()

    def _init_persistence(self):
        from appdirs import user_cache_dir

        self.persist_dir = Path(user_cache_dir(appname=self.persist_dir))
        self.persist_dir.mkdir(parents=True, exist_ok=True)

    def _persist_data(self, data_type: str, data: Union[List[str], Dict]):
        file_path = self.persist_dir / f"{data_type}.json"
        try:
            with open(file_path, "w") as f:
                json.dump(data, f)
            logger.debug(f"Persisted {data_type} to {file_path}")
        except Exception as e:
            logger.error(f"Failed to persist {data_type}: {e}")

    def _configure_paths(self):
        rh_config = self.config["remote_hosts"]
        self.file_paths = {
            "remote_hosts": {
                "msft": self.static_dir / rh_config["msft"],
                "aggressive": self.static_dir / rh_config["aggressive"],
                "others": self.static_dir / rh_config["others"],
            },
            "user_agents": self.static_dir / self.config["user_agents"]["filename"],
            "redirect_domains": self.static_dir
            / self.config["redirect_domains"]["filename"],
        }

    async def initialize(self):
        await self._load_all_data()

    async def _load_all_data(self):
        try:
            self.remote_hosts["msft"] = await self._load_json_file(
                self.file_paths["remote_hosts"]["msft"]
            )
            self.remote_hosts["aggressive"] = await self._load_json_file(
                self.file_paths["remote_hosts"]["aggressive"]
            )
            self.remote_hosts["others"] = await self._load_json_file(
                self.file_paths["remote_hosts"]["others"]
            )

            self.user_agents = await self._load_json_file(
                self.file_paths["user_agents"]
            )

            raw_domains = await self._load_json_file(
                self.file_paths["redirect_domains"]
            )
            self.redirect_domains = self._process_domains(raw_domains)

        except Exception as e:
            logger.error(f"Failed to initialize redirect rules: {e}")
            raise

    def get_redirect_rules(
        self, exclude: Optional[Union[str, List[str]]] = None
    ) -> Dict:
        if exclude and not isinstance(exclude, list):
            exclude = [exclude]

        rules = {
            "user_agents": self.user_agents.copy(),
            "remote_hosts": {k: v.copy() for k, v in self.remote_hosts.items()},
            "redirect_domains": self.redirect_domains.copy(),
        }

        if not exclude:
            rules["remote_hosts"] = [
                v for row in rules["remote_hosts"].values() for v in row
            ]
            return rules

        filtered_rules = {}

        for key, item in rules.items():
            if isinstance(item, dict):
                filtered_dict = {}
                for group, members in rules[key].items():
                    if any(re.match(pattern, group) for pattern in exclude):
                        continue
                    filtered_dict[group] = [
                        member
                        for member in members
                        if not any(re.match(pattern, member) for pattern in exclude)
                    ]
                filtered_rules[key] = [v for row in filtered_dict.values() for v in row]
            else:
                filtered_rules[key] = [
                    value
                    for value in rules[key]
                    if not any(re.match(pattern, value) for pattern in exclude)
                ]
        return filtered_rules

    def _process_domains(self, domains: List[str]) -> List[str]:
        processed = []
        for domain in domains:
            if isinstance(domain, str):
                processed.append(
                    domain if domain.startswith("https://") else f"https://{domain}"
                )
            else:
                logger.warning(f"Skipping invalid domain format: {domain}")
        return sorted(processed)

    def add_remote_host(self, host: str, category: str = "custom"):
        if category not in self.remote_hosts:
            raise ValueError(
                f"Invalid category {category}. Valid options: {list(self.remote_hosts.keys())}"
            )

        if host not in self.remote_hosts[category]:
            self.remote_hosts[category].append(host)
            return self.remote_hosts

    def delete_remote_host(self, host: str, category: Optional[str] = None):
        if category and host in self.remote_hosts.get(category, []):
            self.remote_hosts[category].remove(host)
        else:
            for category, hosts in self.remote_hosts.items():
                if host in hosts:
                    self.remote_hosts[category].remove(host)
        return self.remote_hosts

    def get_remote_hosts(self, category: Optional[str] = None) -> List[str]:
        if category:
            return sorted(self.remote_hosts.get(category, []))
        return sorted([h for cat in self.remote_hosts.values() for h in cat])

    def add_user_agent(self, user_agent: str):
        if user_agent and user_agent not in self.user_agents:
            self.user_agents.append(user_agent)
            return self.user_agents

    def delete_user_agent(self, user_agent: str):
        if user_agent in self.user_agents:
            self.user_agents.remove(user_agent)
            return self.user_agents

    def get_user_agents(self) -> List[str]:
        return sorted(self.user_agents)

    def add_redirect_domain(self, domain: str):
        processed = self._process_domains([domain])[0]
        if processed not in self.redirect_domains:
            self.redirect_domains.append(processed)
            return self.redirect_domains

    def delete_redirect_domain(self, domain: str):
        processed = self._process_domains([domain])[0]
        if processed in self.redirect_domains:
            self.redirect_domains.remove(processed)
            return self.redirect_domains

    def get_redirect_domains(self) -> List[str]:
        return sorted(self.redirect_domains)

    @staticmethod
    async def _load_json_file(path: Path) -> List[str]:
        try:
            if path.exists():
                async with aiofiles.open(path, "r") as f:
                    return json.loads(await f.read())
            return []
        except Exception as e:
            logger.error(f"Error loading {path}: {e}")
            return []

    @staticmethod
    async def _save_json_file(data: List[str], path: Path):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            async with aiofiles.open(path, "w") as f:
                await f.write(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Error saving {path}: {e}")
            raise


async def process_ip_ranges(
    ip_config, out_dir: Optional[Path] = NotImplementedError
) -> Dict[str, Any]:
    try:
        exclude_groups = ip_config.get("exclude_groups", [])
        excluded_ips = None
        if "cloudflare" in exclude_groups:
            cloudflare_data = await get_cloudflare_ips(
                jd_cloud=ip_config.get("exclude_cloudflare_jd_cloud", False)
            )
            cdn_ips = cloudflare_data.get("cdn", {})
            excluded_ips = [*cdn_ips.get("ipv4", []), *cdn_ips.get("ipv6", [])]

        ip_manager = IPManager(config=ip_config)
        await ip_manager.initialize()
        ip_ranges = ip_manager.get_ranges(
            exclude_ips=excluded_ips, exclude_groups=exclude_groups
        )

        if out_dir:
            ipv4_singles = [ip for ip in ip_ranges.get("ipv4", []) if "/" not in ip]
            ipv6_singles = [ip for ip in ip_ranges.get("ipv6", []) if "/" not in ip]
            ipv4_cidrs = [ip for ip in ip_ranges.get("ipv4", []) if "/" in ip]
            ipv6_cidrs = [ip for ip in ip_ranges.get("ipv6", []) if "/" in ip]

            ip_singles = [*ipv4_singles, *ipv6_singles]

            filemap = {
                "out_ips_file_name": ip_singles,
                "out_cidrs_ipv4_file_name": ipv4_cidrs,
                "out_cidrs_ipv6_file_name": ipv6_cidrs,
            }
            tasks = [
                save_json_async(ip, Path(out_dir) / ip_config.get(filename))
                for filename, ip in filemap.items()
            ]

            await asyncio.gather(*tasks)

        return ip_ranges

    except Exception as e:
        logger.error(f"Error in ip ranges processing: {e}")
        raise


async def process_redirect_rules(
    config: Dict[str, Any], out_dir: Optional[Path] = None
) -> Dict[str, Any]:
    manager = RedirectRulesManager(config, persist=config["persist"])
    await manager.initialize()
    exclusions = [
        *config.get("exclude", []),
        *config.get("remote_hosts", {}).get("exclude", []),
    ]
    if exclusions:
        logger.debug(f"Excluding the folling {exclusions}")
    redirect_rules = manager.get_redirect_rules(exclude=exclusions)

    if out_dir:
        tasks = [
            save_json_async(content, Path(out_dir) / config[filename]["out_file"])
            for filename, content in redirect_rules.items()
        ]
        await asyncio.gather(*tasks)

    return redirect_rules


async def process_blacklist(config: Dict[str, Any]) -> Dict[str, Any]:
    out_dir = config.get("general", {}).get("out_dir")
    out_dir = Path(out_dir).expanduser().resolve()
    if not out_dir.exists():
        logger.debug(f"Output directory '{out_dir}' does not exist. Creating it...")
        out_dir.mkdir(parents=True, exist_ok=True)

    tasks = [
        process_ip_ranges(config.get("ip_ranges"), out_dir=out_dir),
        process_redirect_rules(config.get("redirect_rules"), out_dir=out_dir),
    ]
    result = await asyncio.gather(*tasks)
    ip_ranges, redirect_rules = result

    return {
        "ip_ranges": ip_ranges,
        "redirect_rules": redirect_rules,
    }
