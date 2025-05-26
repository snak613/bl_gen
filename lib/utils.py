import hashlib
import ipaddress
import json
import os
import re
from ipaddress import IPv4Network, ip_network
from pathlib import Path
from typing import Dict, List, Set, Tuple

import aiofiles
import toml
from loguru import logger


def regex_to_cidr(pattern):
    # Remove ^ at the start and $ at the end if present
    pattern = pattern.strip().strip("^$")

    # Handle patterns ending with .* or .*.*
    if pattern.endswith(".*") or pattern.endswith(".*.*"):
        base_ip = pattern.rstrip(".*")
        parts = base_ip.split(".")
        if len(parts) == 1:
            return f"{base_ip}.0.0.0/8"
        elif len(parts) == 2:
            return f"{base_ip}.0.0/16"
        elif len(parts) == 3:
            return f"{base_ip}.0/24"

    # Handle exact IP matches
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", pattern):
        return pattern

    # Handle patterns with ranges, e.g., 192.168.[0-255].* or 10.[0-9].*
    match = re.match(r"^(\d+\.)(\d+\.)?\[(\d+)-(\d+)\]\.?(.*)$", pattern)
    if match:
        prefix = match.group(1) + (match.group(2) or "")
        start, end = int(match.group(3)), int(match.group(4))
        suffix = match.group(5)

        cidrs = []
        for i in range(start, end + 1):
            if suffix == "*" or suffix == ".*" or suffix == "*.*":
                cidrs.append(f"{prefix}{i}.0/24")
            elif suffix == "":
                cidrs.append(f"{prefix}{i}/24")
            else:
                cidrs.append(f"{prefix}{i}.{suffix}/32")
        return cidrs

    # Handle patterns like 66.211.160.86*
    match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\*$", pattern)
    if match:
        base_ip = match.group(1)
        return f"{base_ip[:-1]}0/24"

    # If no conversion possible, return None
    return None


def sort_ips(ip_list: List[str]) -> List[str]:
    def ip_key(ip_string):
        normalized_ip = normalize_ip(ip_string.strip())
        network = ip_network(normalized_ip, strict=False)
        # False comes before True
        return (
            not isinstance(network, IPv4Network),
            network.network_address._ip,
            network.prefixlen,
        )

    ip_list = map(lambda s: s.lstrip("0"), ip_list)
    ip_list = filter(is_valid_ip, ip_list)
    return sorted(ip_list, key=ip_key)


def normalize_ip_cidr(ip):
    # Convert /31 and /32 CIDRs to single IP
    ip = re.sub("/3[12]", "", ip)

    # Convert lower-bound CIDRs into /24 by default
    # This is assmuming that if a portion of the net
    # was seen, we want to avoid the full netblock
    # added \
    ip = re.sub("\\.[0-9]{1,3}/(2[456789]|30)", ".0/24", ip)
    return ip


def normalize_ip(ip_string: str) -> str:
    ip_string = ip_string.lstrip("0")
    if "/" in ip_string:
        ip, cidr = ip_string.split("/")
        if ":" in ip:
            return f"{ip}/{cidr}"

        octets = [str(int(octet)) for octet in ip.split(".") if octet]
        return f"{'.'.join(octets)}/{cidr}"
    else:
        if ":" in ip_string:
            return ip_string

        octets = [str(int(octet)) for octet in ip_string.split(".") if octet]
        return ".".join(octets)


def save_json(json_data, filepath, **kwargs):
    indent = kwargs.get("indent") or 3
    kwargs["indent"] = indent
    with open(filepath, "w") as fd:
        json.dump(json_data, fd, **kwargs)
        logger.debug(f"Done saving json data to {filepath}")


async def save_json_async(data, filename):
    async with aiofiles.open(filename, mode="w") as f:
        await f.write(json.dumps(data))
        logger.debug(f"Saved to {filename}")


def load_json(filepath, **kwargs):
    try:
        with open(filepath) as fd:
            out = json.load(fd, **kwargs)
            return out
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.debug(f"filepath {filepath} load failed: {e}")


async def load_json_async(filepath, **kwargs):
    try:
        async with aiofiles.open(filepath, mode="r") as fd:
            content = await fd.read()
            out = json.loads(content, **kwargs)
            return out
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.debug(f"filepath {filepath} load failed: {e}")


def write_list(
    my_list,
    filepath,
    mode="a",
    prefix="",
):
    with open(filepath, mode=mode) as f:
        f.writelines(prefix + "{}\n".format(x) for x in my_list)
    logger.debug(f"Successfully written to {filepath}")


def is_valid_ip(ip):
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False


def is_valid_ipv4(ip: str) -> bool:
    try:
        network = ipaddress.ip_network(ip, strict=False)
        return isinstance(network, ipaddress.IPv4Network)
    except ValueError:
        return False


def is_valid_ipv6(ip: str) -> bool:
    try:
        network = ipaddress.ip_network(ip, strict=False)
        return isinstance(network, ipaddress.IPv6Network)
    except ValueError:
        return False


def clean_content(content: str) -> str:
    # Replace tabs and multiple spaces with single space
    content = re.sub(r"\s+", " ", content)
    # Remove any whitespace around IP addresses
    content = re.sub(r"\s*((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)\s*", r"\1", content)
    content = re.sub(
        r"\s*((?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}(?:/\d{1,3})?)\s*",
        r"\1",
        content,
    )
    content = content.replace(r"\t", "")

    return content


def extract_ips(content: str) -> List[str]:
    """
    Extract IP addresses from plain text.
    Handles both IPv4 and IPv6 addresses and CIDR ranges.
    """

    content = clean_content(content)

    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"

    ipv6_pattern = r"""
        \b
        (?:
            (?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|
            (?:[0-9a-fA-F]{1,4}:){1,7}:|
            (?:::(?:[0-9a-fA-F]{1,4}:){0,6})|
            (?:[0-9a-fA-F]{1,4}:){1,7}:
        )
        (?:[0-9a-fA-F]{1,4})?
        (?:/\d{1,3})?
        \b
    """

    potential_ips = set()

    ipv4_matches = re.findall(ipv4_pattern, content)
    potential_ips.update(ipv4_matches)

    ipv6_matches = re.findall(ipv6_pattern, content, re.VERBOSE)
    potential_ips.update(ipv6_matches)

    json_ip_pattern = r'"ip_address":\s*"([^"]+)"'
    json_matches = re.findall(json_ip_pattern, content)
    potential_ips.update(json_matches)

    return [ip for ip in potential_ips if is_valid_ip(ip)]


# def extract_ips(content: str) -> List[str]:
#     """
#     Extract IP addresses from plain text.
#     Handles both IPv4 and IPv6 addresses and CIDR ranges.
#     """

#     content = clean_content(content)

#     ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"

#     ipv6_pattern = r"""
#         \b
#         (?:
#             (?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|
#             (?:[0-9a-fA-F]{1,4}:){1,7}:|
#             (?:::(?:[0-9a-fA-F]{1,4}:){0,6})|
#             (?:[0-9a-fA-F]{1,4}:){1,7}:
#         )
#         (?:[0-9a-fA-F]{1,4})?
#         (?:/\d{1,3})?
#         \b
#     """

#     potential_ips = set(re.findall(ipv4_pattern, content))
#     potential_ips.update(re.findall(ipv6_pattern, content, re.VERBOSE))

#     return [ip for ip in potential_ips if is_valid_ip(ip)]


def extract_ips2(content):
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
    potential_ips = re.findall(ip_pattern, content)
    valid_ips = [ip for ip in potential_ips if is_valid_ip(ip)]
    return valid_ips


def extract_cidr_ips(content: str) -> Dict[str, List[str]]:
    """
    Extract only IP ranges in CIDR notation (both IPv4 and IPv6)
    """
    # IPv4 CIDR pattern: Requires the /prefix part
    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b"

    # IPv6 CIDR pattern: Requires the /prefix part
    ipv6_pattern = r"\b(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:::(?:[0-9a-fA-F]{1,4}:){0,6})|(?:[0-9a-fA-F]{1,4}:){1,7}:)(?:[0-9a-fA-F]{1,4})?/\d{1,3}\b"

    ipv4_ranges = [ip for ip in re.findall(ipv4_pattern, content) if is_valid_ip(ip)]
    ipv6_ranges = [ip for ip in re.findall(ipv6_pattern, content) if is_valid_ip(ip)]

    return [*ipv4_ranges, *ipv6_ranges]


def convert_range_to_cidrs(start_ip: str, end_ip: str) -> List[str]:
    try:
        # Detect IP version based on presence of colons
        if ":" in start_ip:
            start = ipaddress.IPv6Address(start_ip)
            end = ipaddress.IPv6Address(end_ip)
        else:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
        return [str(cidr) for cidr in ipaddress.summarize_address_range(start, end)]
    except ValueError as e:
        logger.warning(f"Invalid IP range {start_ip}-{end_ip}: {e}")
        return []


def get_module_dir() -> Path:
    return Path(os.path.dirname(os.path.abspath(__file__)))


def read_split(filepath, splitby="ip ", skip=";"):
    with open(filepath) as f:
        return [
            line.split(splitby)[-1].strip(";")
            for line in f
            if not line.startswith(skip)
        ]


def remove_empty(items):
    return [item.strip("\n").strip(";").strip() for item in items if item]


def get_hash(content):
    return hashlib.md5(content).hexdigest()


class IPCompiler:
    def __init__(self):
        self.networks: Set[IPv4Network] = set()
        self.merge_history: Dict[str, List[str]] = {}

    def add_ip(self, ip_str: str) -> None:
        try:
            if "/" in ip_str:
                network = IPv4Network(ip_str, strict=False)
                self.networks.add(network)
                self.merge_history[str(network)] = [ip_str]
            else:
                network = IPv4Network(f"{ip_str}/32", strict=False)
                self.networks.add(network)
                self.merge_history[str(network)] = [ip_str]
        except ValueError as e:
            raise ValueError(f"Invalid IP address or CIDR block: {ip_str}") from e

    def _can_merge(self, net1: IPv4Network, net2: IPv4Network) -> bool:
        try:
            combined = net1.supernet(new_prefix=net1.prefixlen - 1)
            return combined.network_address == net1.network_address and net2 in combined
        except ValueError:
            return False

    def _merge_networks(self, networks: List[IPv4Network]) -> List[IPv4Network]:
        if not networks:
            return []
        networks = sorted(networks, key=lambda x: (x.network_address, x.prefixlen))

        merged = True
        while merged:
            merged = False
            result = []
            i = 0
            while i < len(networks):
                if i + 1 < len(networks) and self._can_merge(
                    networks[i], networks[i + 1]
                ):
                    # Merge networks and update history
                    combined = networks[i].supernet(
                        new_prefix=networks[i].prefixlen - 1
                    )
                    # Update merge history for the new combined network
                    self.merge_history[str(combined)] = self.merge_history.get(
                        str(networks[i]), []
                    ) + self.merge_history.get(str(networks[i + 1]), [])
                    # Clean up old history entries
                    self.merge_history.pop(str(networks[i]), None)
                    self.merge_history.pop(str(networks[i + 1]), None)

                    result.append(combined)
                    i += 2
                    merged = True
                else:
                    result.append(networks[i])
                    i += 1
            networks = result

        return networks

    def compile(self) -> Tuple[List[str], Dict[str, List[str]]]:
        if not self.networks:
            return [], {}

        optimized = self._merge_networks(list(self.networks))

        optimized_cidrs = [
            str(network)
            for network in sorted(optimized, key=lambda x: x.network_address)
        ]

        return optimized_cidrs, self.merge_history


def compile_ip_addresses(ip_list: List[str]) -> Tuple[List[str], Dict[str, List[str]]]:
    compiler = IPCompiler()
    for ip in ip_list:
        compiler.add_ip(ip)
    return compiler.compile()


def load_config(config_path):
    try:
        config = toml.load(config_path)
        return config
    except Exception as e:
        logger.error(f"Failed to load configuration from config.toml: {e}")
        raise
