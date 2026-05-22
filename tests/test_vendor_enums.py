import pytest
from core.vendor.enums import FeatureKey, FeatureSupportStatus, ForbiddenPatternCategory


class TestFeatureKey:
    def test_vlan(self):
        assert FeatureKey.VLAN.value == "vlan"

    def test_svi(self):
        assert FeatureKey.SVI.value == "svi"

    def test_trunk(self):
        assert FeatureKey.TRUNK.value == "trunk"

    def test_stp(self):
        assert FeatureKey.STP.value == "stp"

    def test_lacp(self):
        assert FeatureKey.LACP.value == "lacp"

    def test_same_instance_as_domain_base(self):
        from core.domain.base import FeatureKey as DomainFK
        assert FeatureKey.VLAN == DomainFK.VLAN
        assert FeatureKey is DomainFK


class TestFeatureSupportStatus:
    def test_full(self):
        assert FeatureSupportStatus.FULL.value == "full"

    def test_partial(self):
        assert FeatureSupportStatus.PARTIAL.value == "partial"

    def test_unsupported(self):
        assert FeatureSupportStatus.UNSUPPORTED.value == "unsupported"

    def test_unknown(self):
        assert FeatureSupportStatus.UNKNOWN.value == "unknown"

    def test_four_members(self):
        assert len(FeatureSupportStatus) == 4


class TestForbiddenPatternCategory:
    def test_residual(self):
        assert ForbiddenPatternCategory.RESIDUAL_SYNTAX.value == "residual_syntax"

    def test_dangerous(self):
        assert ForbiddenPatternCategory.DANGEROUS_COMMAND.value == "dangerous_command"

    def test_unsupported(self):
        assert ForbiddenPatternCategory.UNSUPPORTED_FEATURE.value == "unsupported_feature"

    def test_style(self):
        assert ForbiddenPatternCategory.STYLE_WARNING.value == "style_warning"

    def test_four_members(self):
        assert len(ForbiddenPatternCategory) == 4
