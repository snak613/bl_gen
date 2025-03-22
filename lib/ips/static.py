from typing import Dict, List, Optional

from ..utils import (
    extract_ips,
    get_module_dir,
    is_valid_ipv4,
    is_valid_ipv6,
    load_json,
    sort_ips,
)


def get_extra_ranges(
    filename: Optional[str] = None,
) -> Dict[str, Dict[str, List[str]]]:
    script_dir = get_module_dir()
    filename = filename or script_dir / "static" / "extra_ranges.json"
    return load_json(filename)


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
