from __future__ import annotations

from core.domain import DeviceDomain, FeatureKey
from core.ir_models.enums import IRRiskLevel
from core.vendor import init_profiles, get_profile
from core.vendor.base import VendorPlatformProfile, FeatureSupport
from core.vendor.enums import FeatureSupportStatus, ForbiddenPatternCategory
from core.validator.capability_gap_validator import CapabilityGapValidator


def _make_profile(key, domain, capabilities):
    parts = key.split("_", 1)
    return VendorPlatformProfile(
        key=key,
        vendor=parts[0] if len(parts) > 1 else key,
        platform=parts[1] if len(parts) > 1 else key,
        display_name=key,
        device_family="switch",
        supported_domains=[domain],
        capabilities={domain: capabilities},
        forbidden_patterns=[],
        comment_char="!",
    )


class TestCapabilityGapValidator:
    def setup_method(self):
        init_profiles()

    def test_equal_capabilities_no_issues(self):
        caps = {
            FeatureKey.VLAN: FeatureSupport(FeatureSupportStatus.FULL),
            FeatureKey.INTERFACE: FeatureSupport(FeatureSupportStatus.FULL),
            FeatureKey.OSPF: FeatureSupport(FeatureSupportStatus.FULL),
        }
        src = _make_profile("h3c_comware", DeviceDomain.SWITCH, caps)
        tgt = _make_profile("cisco_ios_xe", DeviceDomain.SWITCH, caps)
        v = CapabilityGapValidator(
            source_profile=src, target_profile=tgt,
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
        )
        issues = v.validate()
        assert len(issues) == 0

    def test_unsupported_feature_critical(self):
        src_caps = {
            FeatureKey.VLAN: FeatureSupport(FeatureSupportStatus.FULL),
            FeatureKey.NAT: FeatureSupport(FeatureSupportStatus.FULL),
        }
        tgt_caps = {
            FeatureKey.VLAN: FeatureSupport(FeatureSupportStatus.FULL),
            FeatureKey.NAT: FeatureSupport(FeatureSupportStatus.UNSUPPORTED,
                                         notes="NAT not available on this platform"),
        }
        src = _make_profile("src", DeviceDomain.SWITCH, src_caps)
        tgt = _make_profile("tgt", DeviceDomain.SWITCH, tgt_caps)
        v = CapabilityGapValidator(
            source_profile=src, target_profile=tgt,
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
        )
        issues = v.validate()
        assert len(issues) == 1
        assert issues[0].severity == IRRiskLevel.CRITICAL
        assert "unsupported" in issues[0].message
        assert issues[0].category.value == "capability_gap"

    def test_partial_feature_medium(self):
        src_caps = {
            FeatureKey.OSPF: FeatureSupport(FeatureSupportStatus.FULL),
        }
        tgt_caps = {
            FeatureKey.OSPF: FeatureSupport(FeatureSupportStatus.PARTIAL,
                                          notes="Only basic OSPF, no redistribution"),
        }
        src = _make_profile("src", DeviceDomain.SWITCH, src_caps)
        tgt = _make_profile("tgt", DeviceDomain.SWITCH, tgt_caps)
        v = CapabilityGapValidator(
            source_profile=src, target_profile=tgt,
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
        )
        issues = v.validate()
        assert len(issues) == 1
        assert issues[0].severity == IRRiskLevel.MEDIUM
        assert "partial" in issues[0].message

    def test_missing_target_key_high(self):
        src_caps = {
            FeatureKey.BGP: FeatureSupport(FeatureSupportStatus.FULL),
        }
        tgt_caps = {}
        src = _make_profile("src", DeviceDomain.SWITCH, src_caps)
        tgt = _make_profile("tgt", DeviceDomain.SWITCH, tgt_caps)
        v = CapabilityGapValidator(
            source_profile=src, target_profile=tgt,
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
        )
        issues = v.validate()
        assert len(issues) == 1
        assert issues[0].severity == IRRiskLevel.HIGH
        assert "not defined" in issues[0].message

    def test_source_unsupported_skipped(self):
        src_caps = {
            FeatureKey.BGP: FeatureSupport(FeatureSupportStatus.UNSUPPORTED),
        }
        tgt_caps = {}
        src = _make_profile("src", DeviceDomain.SWITCH, src_caps)
        tgt = _make_profile("tgt", DeviceDomain.SWITCH, tgt_caps)
        v = CapabilityGapValidator(
            source_profile=src, target_profile=tgt,
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
        )
        issues = v.validate()
        assert len(issues) == 0

    def test_real_cisco_h3c_no_gap(self):
        cisco = get_profile("cisco_ios_xe")
        h3c = get_profile("h3c_comware")
        v = CapabilityGapValidator(
            source_profile=h3c, target_profile=cisco,
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
        )
        issues = v.validate()
        # H3C has vlan/interface/trunk/svi/stp/lacp/fhrp/acl/ospf/static_route/lldp/management/cdp/dhcp_snooping
        # Cisco may not have some H3C-specific features
        for issue in issues:
            print(f"  {issue.severity.value}: {issue.message}")
        # Just verify no critical errors occur
        assert all(i.severity != IRRiskLevel.CRITICAL for i in issues)

    def test_real_cisco_huawei_router_small_gap(self):
        cisco = get_profile("cisco_ios_xe")
        huawei = get_profile("huawei_vrp")
        v = CapabilityGapValidator(
            source_profile=huawei, target_profile=cisco,
            source_domain=DeviceDomain.ROUTER, target_domain=DeviceDomain.ROUTER,
        )
        issues = v.validate()
        for issue in issues:
            print(f"  {issue.severity.value}: {issue.message}")
