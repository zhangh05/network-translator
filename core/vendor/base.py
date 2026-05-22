from __future__ import annotations
from dataclasses import dataclass, field
from core.domain import DeviceDomain, FeatureKey
from core.ir_models.enums import IRRiskLevel
from core.vendor.enums import FeatureSupportStatus, ForbiddenPatternCategory


@dataclass
class FeatureSupport:
    status: FeatureSupportStatus
    notes: str | None = None
    modes: list[str] = field(default_factory=list)
    sub_types: list[str] = field(default_factory=list)


@dataclass
class VendorLimitation:
    title: str
    description: str
    domain: DeviceDomain | None = None
    risk_level: IRRiskLevel | None = None


@dataclass
class VendorSignature:
    pattern: str
    weight: int = 5
    domain: DeviceDomain | None = None
    context: str | None = None


@dataclass
class ForbiddenPattern:
    pattern: str
    severity: IRRiskLevel
    category: ForbiddenPatternCategory
    message: str
    target_context: str | None = None
    suggested_action: str | None = None


@dataclass
class InterfaceNaming:
    pattern: str
    svi_prefix: str
    loopback_prefix: str
    port_channel_prefix: str
    tunnel_prefix: str
    management_prefix: str
    subinterface_separator: str
    physical_patterns: list[str] = field(default_factory=list)

    def normalize(self, name: str) -> str:
        """Vendor-specific ifname -> canonical IR name."""
        import re
        m = re.match(r'Vlan[-.\s]?(?:interface|if)?(\d+)', name, re.IGNORECASE)
        if m:
            return f"Vlan{m.group(1)}"
        m = re.match(r'(?:Bridge-Aggregation|Eth-Trunk|Port-Channel|Port-channel|port-channel)[-\s]?(\d+)', name, re.IGNORECASE)
        if m:
            return f"PortChannel{m.group(1)}"
        m = re.match(r'Loop[Bb]ack(\d+)', name)
        if m:
            return f"Loopback{m.group(1)}"
        m = re.match(r'Tunnel(\d+)', name)
        if m:
            return f"Tunnel{m.group(1)}"
        if name.upper() in ("NULL0", "NULL 0", "NULL"):
            return "Null0"
        return name

    def render(self, canonical: str, target_profile: "VendorPlatformProfile") -> str:
        """Canonical IR name -> target vendor-specific name."""
        import re
        if canonical.startswith("Vlan"):
            num = canonical[4:]
            return f"{target_profile.interface_naming.svi_prefix}{num}"
        if canonical.startswith("PortChannel"):
            num = canonical[11:]
            return f"{target_profile.interface_naming.port_channel_prefix}{num}"
        if canonical.startswith("Loopback"):
            return canonical
        if canonical.startswith("Tunnel"):
            return canonical
        if canonical == "Null0":
            return "Null0"
        return canonical


@dataclass
class VendorPlatformProfile:
    key: str
    vendor: str
    platform: str
    display_name: str
    device_family: str
    supported_domains: list[DeviceDomain]
    default_domain: DeviceDomain | None = None
    interface_naming: InterfaceNaming | None = None
    signatures: list[VendorSignature] = field(default_factory=list)
    forbidden_patterns: list[ForbiddenPattern] = field(default_factory=list)
    comment_char: str = "!"
    capabilities: dict[DeviceDomain, dict[FeatureKey, FeatureSupport]] = field(default_factory=dict)
    limitations: list[VendorLimitation] = field(default_factory=list)
