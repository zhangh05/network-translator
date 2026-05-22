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

SWITCH_CAP = {
    FeatureKey.VLAN: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.SVI: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.TRUNK: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.STP: FeatureSupport(FeatureSupportStatus.FULL, modes=["mstp", "rstp", "pvst"]),
    FeatureKey.LACP: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.FHRP: FeatureSupport(FeatureSupportStatus.PARTIAL, notes="VRRP only (no HSRP/GLBP)"),
    FeatureKey.LLDP: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.ACL: FeatureSupport(FeatureSupportStatus.FULL, sub_types=["basic", "advanced", "layer2"]),
    FeatureKey.STATIC_ROUTE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.DHCP_SNOOPING: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.INTERFACE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.MANAGEMENT: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.AAA: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.OSPF: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.BGP: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.NAT: FeatureSupport(FeatureSupportStatus.PARTIAL, notes="NAT limited on Comware switches"),
}

ROUTER_CAP = {
    FeatureKey.INTERFACE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.STATIC_ROUTE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.OSPF: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.BGP: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.VRF: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.PBR: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.ACL: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.NAT: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.IPSEC_VPN: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.MANAGEMENT: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.AAA: FeatureSupport(FeatureSupportStatus.FULL),
}

profile = VendorPlatformProfile(
    key="h3c_comware",
    vendor="h3c",
    platform="comware",
    display_name="H3C Comware",
    device_family="unified",
    supported_domains=[DeviceDomain.SWITCH, DeviceDomain.ROUTER],
    default_domain=DeviceDomain.SWITCH,
    interface_naming=InterfaceNaming(
        pattern=r"(?i)(GigabitEthernet|Ten-GigabitEthernet|FortyGigE|HundredGigE|Vlan-interface|Bridge-Aggregation|LoopBack|NULL|M-Ethernet)\d",
        svi_prefix="Vlan-interface",
        loopback_prefix="LoopBack",
        port_channel_prefix="Bridge-Aggregation",
        tunnel_prefix="Tunnel",
        management_prefix="M-Ethernet",
        subinterface_separator=".",
        physical_patterns=["GigabitEthernet", "Ten-GigabitEthernet", "FortyGigE", "HundredGigE"],
    ),
    signatures=[
        VendorSignature(pattern=r"(?i)^sysname", weight=5),
        VendorSignature(pattern=r"(?i)^vlan \d+", weight=3, domain=DeviceDomain.SWITCH),
        VendorSignature(pattern=r"(?i)vlan batch", weight=4, domain=DeviceDomain.SWITCH),
        VendorSignature(pattern=r"(?i)^interface Vlan-interface", weight=3, domain=DeviceDomain.SWITCH),
        VendorSignature(pattern=r"(?i)undo\s+", weight=2),
        VendorSignature(pattern=r"(?i)port link-type", weight=3, domain=DeviceDomain.SWITCH),
        VendorSignature(pattern=r"(?i)bridge-aggregation", weight=3),
        VendorSignature(pattern=r"(?i)ip route-static", weight=3),
    ],
    forbidden_patterns=[
        ForbiddenPattern(pattern=r"(?i)switchport mode", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="Cisco 'switchport mode' in H3C output", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)hostname\s+", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="Cisco 'hostname' instead of 'sysname'", target_context="config"),
        ForbiddenPattern(pattern=r"(?i)interface Vlan\d+$", severity=IRRiskLevel.MEDIUM, category=ForbiddenPatternCategory.STYLE_WARNING, message="Should be 'interface Vlan-interface' for H3C", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)ip route ", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="Cisco 'ip route' should be 'ip route-static'", target_context="routing"),
        ForbiddenPattern(pattern=r"(?i)interface Port-channel", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="Cisco 'Port-channel' should be 'Bridge-Aggregation'", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)do show\b", severity=IRRiskLevel.MEDIUM, category=ForbiddenPatternCategory.STYLE_WARNING, message="Cisco 'do' command not valid in H3C", target_context="config"),
    ],
    capabilities={
        DeviceDomain.SWITCH: SWITCH_CAP,
        DeviceDomain.ROUTER: ROUTER_CAP,
    },
    limitations=[
        VendorLimitation(title="FHRP limited to VRRP", description="H3C only supports VRRP, no HSRP/GLBP", domain=DeviceDomain.SWITCH),
        VendorLimitation(title="ACL type mapping", description="H3C basic/advanced/layer2 ACL must map to Cisco standard/extended", domain=DeviceDomain.SWITCH),
    ],
)

register_profile(profile)
