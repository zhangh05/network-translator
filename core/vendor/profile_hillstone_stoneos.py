from __future__ import annotations
from core.domain import DeviceDomain, FeatureKey
from core.vendor import register_profile
from core.vendor.base import (
    VendorPlatformProfile, InterfaceNaming, VendorSignature,
    ForbiddenPattern, FeatureSupport, FeatureSupportStatus,
    VendorLimitation,
)
from core.ir_models.enums import IRRiskLevel
from core.vendor.enums import ForbiddenPatternCategory

FIREWALL_CAP = {
    FeatureKey.ZONE: FeatureSupport(FeatureSupportStatus.FULL, modes=["security-zone"]),
    FeatureKey.ADDRESS_OBJECT: FeatureSupport(FeatureSupportStatus.FULL, sub_types=["ip", "network", "range", "fqdn"]),
    FeatureKey.SERVICE_OBJECT: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.SECURITY_POLICY: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.NAT_POLICY: FeatureSupport(FeatureSupportStatus.FULL, modes=["source", "destination", "static"]),
    FeatureKey.IPSEC_VPN: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.HA: FeatureSupport(FeatureSupportStatus.FULL, modes=["active-active", "active-standby"]),
    FeatureKey.INTERFACE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.MANAGEMENT: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.USER_AUTH: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.LOGGING: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.STATIC_ROUTE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.OSPF: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.BGP: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.VLAN: FeatureSupport(FeatureSupportStatus.UNSUPPORTED, notes="Hillstone does not handle L2 VLAN"),
    FeatureKey.SVI: FeatureSupport(FeatureSupportStatus.UNSUPPORTED),
}

profile = VendorPlatformProfile(
    key="hillstone_stoneos",
    vendor="hillstone",
    platform="stoneos",
    display_name="Hillstone StoneOS",
    device_family="firewall",
    supported_domains=[DeviceDomain.FIREWALL],
    default_domain=DeviceDomain.FIREWALL,
    interface_naming=InterfaceNaming(
        pattern=r"(?i)(GigabitEthernet|XGigabitEthernet|40GE|100GE|Vlan|Loopback|Tunnel|NULL)\d",
        svi_prefix="Vlan",
        loopback_prefix="Loopback",
        port_channel_prefix="Port-channel",
        tunnel_prefix="Tunnel",
        management_prefix="MGT",
        subinterface_separator=".",
        physical_patterns=["GigabitEthernet", "XGigabitEthernet", "40GE", "100GE"],
    ),
    signatures=[
        VendorSignature(pattern=r"(?i)security-zone", weight=5, domain=DeviceDomain.FIREWALL),
        VendorSignature(pattern=r"(?i)^address-group", weight=3, domain=DeviceDomain.FIREWALL),
        VendorSignature(pattern=r"(?i)^service-group", weight=3, domain=DeviceDomain.FIREWALL),
        VendorSignature(pattern=r"(?i)^rule\s+\(", weight=4, domain=DeviceDomain.FIREWALL),
    ],
    forbidden_patterns=[
        ForbiddenPattern(pattern=r"(?i)switchport", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="Switch command in Hillstone firewall config", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)spanning-tree", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.UNSUPPORTED_FEATURE, message="STP not applicable on firewall", target_context="config"),
        ForbiddenPattern(pattern=r"(?i)vlan batch", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C/Huawei VLAN syntax", target_context="vlan"),
        ForbiddenPattern(pattern=r"(?i)ip route-static", severity=IRRiskLevel.MEDIUM, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C/Huawei route syntax", target_context="routing"),
    ],
    capabilities={DeviceDomain.FIREWALL: FIREWALL_CAP},
    limitations=[
        VendorLimitation(title="No L2 switching", description="Hillstone has no L2 VLAN/SVI support", domain=DeviceDomain.FIREWALL),
        VendorLimitation(title="Zone model", description="Zone-based policy model differs from Cisco", domain=DeviceDomain.FIREWALL),
    ],
)

register_profile(profile)
