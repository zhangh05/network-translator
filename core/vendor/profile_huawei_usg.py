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
    FeatureKey.ZONE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.ADDRESS_OBJECT: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.SERVICE_OBJECT: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.SECURITY_POLICY: FeatureSupport(FeatureSupportStatus.FULL, modes=["interzone", "intrazone"]),
    FeatureKey.NAT_POLICY: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.IPSEC_VPN: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.HA: FeatureSupport(FeatureSupportStatus.FULL, modes=["active-active", "active-standby"]),
    FeatureKey.INTERFACE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.VLAN: FeatureSupport(FeatureSupportStatus.PARTIAL, notes="Sub-interface based VLAN on USG"),
    FeatureKey.SVI: FeatureSupport(FeatureSupportStatus.UNSUPPORTED),
    FeatureKey.STATIC_ROUTE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.OSPF: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.BGP: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.AAA: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.MANAGEMENT: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.USER_AUTH: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.LOGGING: FeatureSupport(FeatureSupportStatus.FULL),
}

profile = VendorPlatformProfile(
    key="huawei_usg",
    vendor="huawei",
    platform="usg",
    display_name="Huawei USG",
    device_family="firewall",
    supported_domains=[DeviceDomain.FIREWALL],
    default_domain=DeviceDomain.FIREWALL,
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
        VendorSignature(pattern=r"(?i)security-zone", weight=5, domain=DeviceDomain.FIREWALL),
        VendorSignature(pattern=r"(?i)^security-policy", weight=4, domain=DeviceDomain.FIREWALL),
        VendorSignature(pattern=r"(?i)^nat server", weight=3, domain=DeviceDomain.FIREWALL),
        VendorSignature(pattern=r"(?i)zone-pair security", weight=4, domain=DeviceDomain.FIREWALL),
    ],
    forbidden_patterns=[
        ForbiddenPattern(pattern=r"(?i)switchport", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="Switch port config in USG firewall output", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)vlan batch", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="VLAN batch not valid on USG", target_context="vlan"),
        ForbiddenPattern(pattern=r"(?i)spanning-tree", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.UNSUPPORTED_FEATURE, message="STP not applicable on firewall", target_context="config"),
    ],
    capabilities={DeviceDomain.FIREWALL: FIREWALL_CAP},
    limitations=[
        VendorLimitation(title="No SVI support", description="USG does not support SVI (VLAN interface)", domain=DeviceDomain.FIREWALL),
        VendorLimitation(title="Zone model", description="USG security zone model differs from Cisco ASA zone model", domain=DeviceDomain.FIREWALL),
    ],
)

register_profile(profile)
