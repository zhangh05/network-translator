from __future__ import annotations

from dataclasses import dataclass, field

from core.domain import DeviceDomain


@dataclass
class IRConfigMeta:
    source_vendor: str
    target_vendor: str
    source_domain: DeviceDomain
    target_domain: DeviceDomain
    source_platform: str
    target_platform: str
    hostname: str | None = None
    detected_domains: list[DeviceDomain] = field(default_factory=list)
    domain_confidence: float = 0.0
    domain_evidence: dict[str, float] = field(default_factory=dict)
    manual_domain_override: DeviceDomain | None = None
    platform: str | None = None
    version: str | None = None
    parser_version: str | None = None
    created_at: str = ""
    warnings: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)


@dataclass
class IRConfig:
    meta: IRConfigMeta
    interfaces: list = field(default_factory=list)
    vlans: list = field(default_factory=list)
    svils: list = field(default_factory=list)
    static_routes: list = field(default_factory=list)
    ospf: list = field(default_factory=list)
    bgp: list = field(default_factory=list)
    acls: list = field(default_factory=list)
    nat_rules: list = field(default_factory=list)
    fhrps: list = field(default_factory=list)
    stps: list = field(default_factory=list)
    zones: list = field(default_factory=list)
    address_objects: list = field(default_factory=list)
    service_objects: list = field(default_factory=list)
    security_policies: list = field(default_factory=list)
    vrfs: list = field(default_factory=list)
    pbrs: list = field(default_factory=list)
    ipsec_vpns: list = field(default_factory=list)
    unsupported: list = field(default_factory=list)
