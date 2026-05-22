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
    FeatureKey.FHRP: FeatureSupport(FeatureSupportStatus.FULL, modes=["vrrp"]),
    FeatureKey.ACL: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.STATIC_ROUTE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.INTERFACE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.MANAGEMENT: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.AAA: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.OSPF: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.BGP: FeatureSupport(FeatureSupportStatus.FULL),
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
}

profile = VendorPlatformProfile(
    key="ruijie_rgos",
    vendor="ruijie",
    platform="rg-os",
    display_name="Ruijie RGOS",
    device_family="unified",
    supported_domains=[DeviceDomain.SWITCH, DeviceDomain.ROUTER],
    default_domain=DeviceDomain.SWITCH,
    interface_naming=InterfaceNaming(
        pattern=r"(?i)(GigabitEthernet|FastEthernet|TenGigabitEthernet|Vlan|Port-channel|Loopback|Tunnel|NULL)\d",
        svi_prefix="Vlan",
        loopback_prefix="Loopback",
        port_channel_prefix="Port-channel",
        tunnel_prefix="Tunnel",
        management_prefix="M-GE",
        subinterface_separator=".",
        physical_patterns=["GigabitEthernet", "FastEthernet", "TenGigabitEthernet"],
    ),
    signatures=[
        VendorSignature(pattern=r"(?i)^hostname", weight=3),
        VendorSignature(pattern=r"(?i)^vlan \d+", weight=3, domain=DeviceDomain.SWITCH),
        VendorSignature(pattern=r"(?i)^interface Vlan", weight=2, domain=DeviceDomain.SWITCH),
    ],
    forbidden_patterns=[
        ForbiddenPattern(pattern=r"(?i)sysname\s+", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C/Huawei 'sysname' in Ruijie output", target_context="config"),
        ForbiddenPattern(pattern=r"(?i)undo\s+", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C/Huawei 'undo' in Ruijie output", target_context="config"),
        ForbiddenPattern(pattern=r"(?i)vlan batch", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C/Huawei 'vlan batch' in Ruijie output", target_context="vlan"),
        ForbiddenPattern(pattern=r"(?i)interface Vlan-interface", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C SVI syntax in Ruijie output", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)ip route-static", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C/Huawei 'ip route-static' should be 'ip route'", target_context="routing"),
    ],
    capabilities={
        DeviceDomain.SWITCH: SWITCH_CAP,
        DeviceDomain.ROUTER: ROUTER_CAP,
    },
    limitations=[
        VendorLimitation(title="FHRP limited to VRRP", description="Ruijie only supports VRRP, no HSRP", domain=DeviceDomain.SWITCH),
    ],
)

register_profile(profile)
