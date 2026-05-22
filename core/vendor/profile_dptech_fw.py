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
    FeatureKey.SECURITY_POLICY: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.NAT_POLICY: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.IPSEC_VPN: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.INTERFACE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.MANAGEMENT: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.STATIC_ROUTE: FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.OSPF: FeatureSupport(FeatureSupportStatus.PARTIAL, notes="OSPF support limited"),
    FeatureKey.VLAN: FeatureSupport(FeatureSupportStatus.UNSUPPORTED),
    FeatureKey.SVI: FeatureSupport(FeatureSupportStatus.UNSUPPORTED),
}

profile = VendorPlatformProfile(
    key="dptech_fw",
    vendor="dptech",
    platform="dp-firewall",
    display_name="DPtech Firewall",
    device_family="firewall",
    supported_domains=[DeviceDomain.FIREWALL],
    default_domain=DeviceDomain.FIREWALL,
    interface_naming=InterfaceNaming(
        pattern=r"(?i)(GigabitEthernet|Vlan|Loopback|Tunnel|NULL)\d",
        svi_prefix="Vlan",
        loopback_prefix="Loopback",
        port_channel_prefix="Port-channel",
        tunnel_prefix="Tunnel",
        management_prefix="MGT",
        subinterface_separator=".",
        physical_patterns=["GigabitEthernet"],
    ),
    signatures=[
        VendorSignature(pattern=r"(?i)security-zone", weight=4, domain=DeviceDomain.FIREWALL),
        VendorSignature(pattern=r"(?i)address-group", weight=2, domain=DeviceDomain.FIREWALL),
        VendorSignature(pattern=r"(?i)nat-policy", weight=3, domain=DeviceDomain.FIREWALL),
    ],
    forbidden_patterns=[
        ForbiddenPattern(pattern=r"(?i)switchport", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="Switch command in DPtech firewall config", target_context="interface"),
        ForbiddenPattern(pattern=r"(?i)spanning-tree", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.UNSUPPORTED_FEATURE, message="STP not applicable on firewall", target_context="config"),
        ForbiddenPattern(pattern=r"(?i)vlan batch", severity=IRRiskLevel.HIGH, category=ForbiddenPatternCategory.RESIDUAL_SYNTAX, message="H3C/Huawei VLAN syntax", target_context="vlan"),
    ],
    capabilities={DeviceDomain.FIREWALL: FIREWALL_CAP},
    limitations=[
        VendorLimitation(title="Limited routing", description="OSPF support limited on DPtech firewall", domain=DeviceDomain.FIREWALL),
        VendorLimitation(title="No L2 switching", description="No VLAN/SVI support", domain=DeviceDomain.FIREWALL),
    ],
)

register_profile(profile)
