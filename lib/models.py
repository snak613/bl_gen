from pathlib import Path
from typing import Dict, List, Optional, Union

import toml
from http_client.models import ClientConfig
from pydantic import BaseModel, ConfigDict, Field, field_validator

SECOND = 1
MINUTE = 60 * SECOND
HOUR = 60 * MINUTE

units_map = {
    "y": HOUR * 24 * 365,
    "w": HOUR * 24 * 7,
    "d": HOUR * 24,
    "h": HOUR,
    "m": MINUTE,
    "s": SECOND,
    "ms": 1e-3,
    "us": 1e-6,
}


class UpdaterConfig(BaseModel):
    app_name: str = "python-resource-updater"
    version: Optional[str] = None
    cache_ttl: Optional[float] = Field(None, alias="ttl")
    cache_dir: Optional[Path] = None
    use_system_cache: bool = True
    in_memory_fallback: bool = True

    model_config = ConfigDict(populate_by_name=True)

    @field_validator("cache_ttl", mode="before")
    @classmethod
    def validate_ttl(cls, v) -> float:
        print(v)
        try:
            unit = 1
            if isinstance(v, str) and v[-1] in units_map.keys():
                unit = units_map.get(v[-1])
                v = v[:-1]
            return float(v) * unit
        except Exception:
            return 5 * units_map["h"]

    # @field_validator("cache_dir", mode="before")
    # @classmethod
    # def validate_cache_dir(cls, v):
    #     if v == "":
    #         return
    #     return v


class IPRangesConfig(BaseModel):
    exclude_groups: List[str] = Field(
        default_factory=lambda: [
            "cloudflare",
            "jlang_tor",
            "amazon,aws,microsoft,azure",
            "amazon,aws",
            "microsoft,azure",
        ]
    )
    exclude_cloudflare_jd_cloud: bool = False
    out_ips_file_name: str = "blocked_ips.json"
    out_cidrs_ipv4_file_name: str = "blocked_cidrs_ipv4.json"
    out_cidrs_ipv6_file_name: str = "blocked_cidrs_ipv6.json"
    updater: UpdaterConfig = Field(default_factory=UpdaterConfig)
    sources: Dict[str, UpdaterConfig] = Field(default_factory=dict)


class RemoteHostsConfig(BaseModel):
    exclude: List[str] = Field(default_factory=list)
    msft: str = "msft_remote_hosts.json"
    aggressive: str = "aggressive_remote_hosts.json"
    others: str = "other_remote_hosts.json"
    out_file: Optional[str] = "blocked_remote_hosts.json"


class UserAgentsConfig(BaseModel):
    filename: str = "user_agents.json"
    out_file: Optional[str] = "blocked_user_agents.json"


class RedirectDomainsConfig(BaseModel):
    filename: str = "redirect_domains.json"
    out_file: Optional[str] = "redirect_domains.json"


class RedirectRulesConfig(BaseModel):
    exclude: List[str] = Field(default_factory=list)
    persist: bool = False
    remote_hosts: RemoteHostsConfig = Field(default_factory=RemoteHostsConfig)
    user_agents: UserAgentsConfig = Field(default_factory=UserAgentsConfig)
    redirect_domains: RedirectDomainsConfig = Field(
        default_factory=RedirectDomainsConfig
    )


class GeneralConfig(BaseModel):
    out_dir: Union[str, Path] = "out"
    force_refresh: bool = False
    persist_dir: Union[str, Path] = ""

    @field_validator("out_dir", "persist_dir")
    def validate_path(cls, v):
        if v == "":
            return None
        return Path(v)


class Config(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    ip_ranges: IPRangesConfig = Field(default_factory=IPRangesConfig)
    redirect_rules: RedirectRulesConfig = Field(default_factory=RedirectRulesConfig)
    client: ClientConfig = Field(default_factory=ClientConfig)

    @classmethod
    def from_toml(cls, toml_file: str) -> "Config":
        config_dict = toml.load(toml_file)
        return cls.model_validate(config_dict)
