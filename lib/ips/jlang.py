from typing import Any, Dict, Optional

from ..updater import ResourceUpdater
from ..utils import extract_ips, is_valid_ipv4, is_valid_ipv6


async def get_jlang_htaccess(
    url="https://gist.githubusercontent.com/curi0usJack/971385e8334e189d93a6cb4671238b10/raw/13b11edf67f746bdd940ff3f2e9b8dc18f8ad7d4/.htaccess",
    updater_config: Optional[Dict[str, Any]] = None,
    client_config: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
):
    updater_config = updater_config or {}
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
