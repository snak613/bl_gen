import asyncio
from typing import Any, Dict, List, Optional

from loguru import logger

from ..models import UpdaterConfig
from . import (
    get_asn_ranges_by_name,
    get_aws_ips,
    get_azure_ips,
    get_blocklist_de,
    get_cloudflare_ips,
    get_digitalocean_ips,
    get_forcepoint_ips,
    get_fortinet_ips,
    get_github_ips,
    get_google_ips,
    get_ipsum_ips,
    get_isc_thread_category,
    get_jlang_htaccess,
    get_linode_ips,
    get_microsoft_eop_ranges,
    get_microsoft_ip_tracker_ranges,
    get_microsoft_public_ips,
    get_multiple_tag_ranges,
    get_other_asn_ranges,
    get_paloalto_ips,
    get_symantec_ranges,
    get_tor_exit_nodes,
    get_zscaler_ips,
)
from .static import get_extra_ranges, get_spread_ranges, get_regex_ranges, get_bl_ranges


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
