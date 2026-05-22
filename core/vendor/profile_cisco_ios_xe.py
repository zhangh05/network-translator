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
    FeatureKey.STP: FeatureSupport(FeatureSupportStatus.FULL, modes=["mstp", "rstp", "pvst", "rapid-pvst"]),
    FeatureKey.LACP: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.FHRP: FeatureSupport(FeatureSupportStatus.FULL, modes=["vrrp", "hsrp", "glbp"]),
    FeatureKey.LLDP: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.CDP: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.ACL: FeatureSupport(FeatureSupportStatus.FULL, sub_types=["standard", "extended"]),
    FeatureKey.STATIC_ROUTE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.DHCP_SNOOPING: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.INTERFACE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.MANAGEMENT: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.AAA: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.OSPF: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.BGP: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.NAT: FeatureSupport(FeatureSupportStatus.PARTIAL, notes="Router-style NAT only"),
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
    key="cisco_ios_xe",
    vendor="cisco",
    platform="ios-xe",
    display_name="Cisco IOS-XE",
    device_family="unified",
    supported_domains=[DeviceDomain.SWITCH, DeviceDomain.ROUTER],
    default_domain=DeviceDomain.SWITCH,
    interface_naming=InterfaceNaming(
        pattern=r"(?i)(GigabitEthernet|FastEthernet|TenGigabitEthernet|FortyGigabitEthernet|HundredGigE|Vlan|Port-channel|Loopback|Tunnel|Management|Null)\d",
        svi_prefix="Vlan",
        loopback_prefix="Loopback",
        port_channel_prefix="Port-channel",
        tunnel_prefix="Tunnel",
        management_prefix="Management",
        subinterface_separator=".",
        physical_patterns=["GigabitEthernet", "FastEthernet", "TenGigabitEthernet", "FortyGigabitEthernet", "HundredGigE"],
    ),
    signatures=[
        VendorSignature(pattern=r"(?i)^interface", weight=3),
        VendorSignature(pattern=r"(?i)^router ospf", weight=5, domain=DeviceDomain.ROUTER),
        VendorSignature(pattern=r"(?i)^router bgp", weight=5, domain=DeviceDomain.ROUTER),
        VendorSignature(pattern=r"(?i)^vlan \d+", weight=3, domain=DeviceDomain.SWITCH),
    ],
    forbidden_patterns=[
        ForbiddenPattern(pattern=r"(?i)undo\s+", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C 'undo' command pattern found in Cisco output", target_context="config"),
        ForbiddenPattern(pattern=r"(?i)sysname\s+", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C 'sysname' instead of 'hostname'", target_context="config"),
        ForbiddenPattern(pattern=r"(?i)vlan batch", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C 'vlan batch' not valid in Cisco config", target_context="vlan"),
        ForbiddenPattern(pattern=r"(?i)interface Vlan-interface", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C SVI syntax should be 'interface Vlan'", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)ospf\s+\d+\s+vpn-instance", severity=IRRiskLevel.MEDIUM, category=ForbiddenPatternCategory.UNSUPPORTED_FEATURE, message="OSPF VPN instance not directly supported", target_context="routing"),
        ForbiddenPattern(pattern=r"(?i)ip binding vpn-instance", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.UNSUPPORTED_FEATURE, message="VPN instance binding syntax different", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)port link-type", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C 'port link-type' should be 'switchport mode'", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)bridge-aggregation", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C 'bridge-aggregation' should be 'port-channel'", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)interface Eth-Trunk", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="Huawei 'Eth-Trunk' should be 'interface Port-channel'", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)traffic-filter", severity=IRRiskLevel.MEDIUM, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C/Huawei 'traffic-filter' syntax in Cisco output", target_context="acl"),
        ForbiddenPattern(pattern=r"(?i)ip route-static", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C/Huawei 'ip route-static' should be 'ip route'", target_context="routing"),
        ForbiddenPattern(pattern=r"(?i)commit\b", severity=IRRiskLevel.MEDIUM, category=ForbiddenPatternCategory.STYLE_WARNING, message="Unnecessary commit in Cisco config", target_context="config"),
    ],
    capabilities={
        DeviceDomain.SWITCH: SWITCH_CAP,
        DeviceDomain.ROUTER: ROUTER_CAP,
    },
    limitations=[
        VendorLimitation(title="NAT semantic mapping", description="Router NAT from H3C/Huawei to Cisco may have semantic gaps in inside/outside mapping", domain=DeviceDomain.ROUTER),
    ],
)

register_profile(profile)
