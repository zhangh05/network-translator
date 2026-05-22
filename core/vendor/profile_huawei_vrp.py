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
    FeatureKey.STP: FeatureSupport(FeatureSupportStatus.FULL, modes=["mstp", "rstp", "stp"]),
    FeatureKey.LACP: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.FHRP: FeatureSupport(FeatureSupportStatus.PARTIAL, notes="VRRP only"),
    FeatureKey.LLDP: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.ACL: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.STATIC_ROUTE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.INTERFACE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.MANAGEMENT: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.AAA: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.OSPF: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.BGP: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.NAT: FeatureSupport(FeatureSupportStatus.PARTIAL),
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
    key="huawei_vrp",
    vendor="huawei",
    platform="vrp",
    display_name="Huawei VRP",
    device_family="unified",
    supported_domains=[DeviceDomain.SWITCH, DeviceDomain.ROUTER],
    default_domain=DeviceDomain.ROUTER,
    comment_char="#",
    interface_naming=InterfaceNaming(
        pattern=r"(?i)(GigabitEthernet|XGigabitEthernet|40GE|100GE|Vlanif|Eth-Trunk|LoopBack|NULL|MEth)\d",
        svi_prefix="Vlanif",
        loopback_prefix="LoopBack",
        port_channel_prefix="Eth-Trunk",
        tunnel_prefix="Tunnel",
        management_prefix="MEth",
        subinterface_separator=".",
        physical_patterns=["GigabitEthernet", "XGigabitEthernet", "40GE", "100GE"],
    ),
    signatures=[
        VendorSignature(pattern=r"(?i)^sysname", weight=5),
        VendorSignature(pattern=r"(?i)^vlan batch", weight=4, domain=DeviceDomain.SWITCH),
        VendorSignature(pattern=r"(?i)^interface Vlanif", weight=3, domain=DeviceDomain.SWITCH),
        VendorSignature(pattern=r"(?i)ip route-static", weight=3),
        VendorSignature(pattern=r"(?i)interface Eth-Trunk", weight=3),
        VendorSignature(pattern=r"(?i)undo\s+", weight=2),
    ],
    forbidden_patterns=[
        ForbiddenPattern(pattern=r"(?i)switchport", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="Cisco 'switchport' in Huawei output", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)hostname\s+", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="Cisco 'hostname' in Huawei output", target_context="config"),
        ForbiddenPattern(pattern=r"(?i)interface Vlan-interface", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C-style 'Vlan-interface' for Huawei ('Vlanif')", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)interface Vlan\d+$", severity=IRRiskLevel.MEDIUM, category=ForbiddenPatternCategory.STYLE_WARNING, message="Cisco-style 'VlanN' should be 'VlanifN'", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)ip route ", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="Cisco 'ip route' should be 'ip route-static'", target_context="routing"),
        ForbiddenPattern(pattern=r"(?i)interface Port-channel", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="Cisco 'Port-channel' should be 'Eth-Trunk'", target_context="interface"),
    ],
    capabilities={
        DeviceDomain.SWITCH: SWITCH_CAP,
        DeviceDomain.ROUTER: ROUTER_CAP,
    },
    limitations=[
        VendorLimitation(title="FHRP limited to VRRP", description="Huawei VRP only supports VRRP", domain=DeviceDomain.SWITCH),
        VendorLimitation(title="ACL numbering differences", description="Huawei ACL numbering ranges differ from Cisco", domain=DeviceDomain.SWITCH),
    ],
)

register_profile(profile)
