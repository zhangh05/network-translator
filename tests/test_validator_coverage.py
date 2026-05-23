from __future__ import annotations

from core.domain import DeviceDomain, DomainProfile, FeatureKey
from core.ir_models import IRConfig, IRConfigMeta
from core.ir_models.base import SourceSpan
from core.ir_models.common import IRInterface, IRStaticRoute
from core.ir_models.enums import IRInterfaceType, IRRiskLevel, IRType
from core.ir_models.switch import IRLag, IRVlan
from core.renderer.base import RenderResult
from core.validator.coverage_validator import (
    CoverageValidator,
    get_feature_mapping,
    _IR_TO_FEATURE,
)


def _make_ir(vlans=None, svis=None, interfaces=None, lags=None,
             static_routes=None, ospf=None, acls=None, stp=None):
    meta = IRConfigMeta(
        source_vendor="h3c", target_vendor="cisco",
        source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
        source_platform="comware", target_platform="ios-xe",
    )
    return IRConfig(meta=meta,
                    vlans=vlans or [],
                    svis=svis or [],
                    interfaces=interfaces or [],
                    lags=lags or [],
                    static_routes=static_routes or [],
                    ospf=ospf or [],
                    acls=acls or [])


def _span():
    return SourceSpan(1, 1, ["line"])


class TestCoverageValidator:
    def test_no_ir_no_render_empty(self):
        v = CoverageValidator(
            src_domain=DeviceDomain.SWITCH,
            tgt_domain=DeviceDomain.SWITCH,
        )
        issues, ir_c, r_n = v.validate(ir=None, render_result=None)
        assert len(issues) == 0
        assert ir_c == {}

    def test_all_features_rendered_no_issues(self):
        ir = _make_ir(
            vlans=[IRVlan(IRType.VLAN, _span(), 10)],
            static_routes=[IRStaticRoute(
                IRType.STATIC_ROUTE, _span(),
                prefix="0.0.0.0", mask="0.0.0.0",
                nexthop="10.0.0.1",
            )],
        )
        rr = RenderResult(config_text="!\n",
                          features_rendered=["vlans", "static_routes"])
        v = CoverageValidator(
            src_domain=DeviceDomain.SWITCH,
            tgt_domain=DeviceDomain.SWITCH,
        )
        issues, ir_c, r_n = v.validate(ir=ir, render_result=rr)
        assert len(issues) == 0

    def test_vlan_in_ir_not_rendered_critical(self):
        ir = _make_ir(
            vlans=[IRVlan(IRType.VLAN, _span(), v)
                   for v in range(1, 11)],
        )
        rr = RenderResult(config_text="", features_rendered=[])
        v = CoverageValidator(
            src_domain=DeviceDomain.SWITCH,
            tgt_domain=DeviceDomain.SWITCH,
        )
        issues, ir_c, r_n = v.validate(ir=ir, render_result=rr)
        vlan_issues = [i for i in issues if "vlans" in i.field]
        assert len(vlan_issues) >= 1
        assert vlan_issues[0].severity == IRRiskLevel.CRITICAL

    def test_single_vlan_not_rendered_high(self):
        ir = _make_ir(
            vlans=[IRVlan(IRType.VLAN, _span(), 10)],
        )
        rr = RenderResult(config_text="", features_rendered=[])
        v = CoverageValidator(
            src_domain=DeviceDomain.SWITCH,
            tgt_domain=DeviceDomain.SWITCH,
        )
        issues, ir_c, r_n = v.validate(ir=ir, render_result=rr)
        vlan_issues = [i for i in issues if "vlans" in i.field]
        assert len(vlan_issues) >= 1
        assert vlan_issues[0].severity == IRRiskLevel.HIGH

    def test_feature_rendered_but_not_ir_no_issue(self):
        ir = _make_ir()
        rr = RenderResult(config_text="", features_rendered=["vlans"])
        v = CoverageValidator(
            src_domain=DeviceDomain.SWITCH,
            tgt_domain=DeviceDomain.SWITCH,
        )
        issues, ir_c, r_n = v.validate(ir=ir, render_result=rr)
        assert len(issues) == 0

    def test_ir_with_data_no_render_no_issue(self):
        ir = _make_ir(
            vlans=[IRVlan(IRType.VLAN, _span(), v) for v in [10, 20]],
        )
        v = CoverageValidator(
            src_domain=DeviceDomain.SWITCH,
            tgt_domain=DeviceDomain.SWITCH,
        )
        issues, ir_c, r_n = v.validate(ir=ir, render_result=None)
        assert len(issues) == 0

    def test_multiple_features_missing(self):
        ir = _make_ir(
            vlans=[IRVlan(IRType.VLAN, _span(), 10)],
            static_routes=[IRStaticRoute(
                IRType.STATIC_ROUTE, _span(),
                prefix="0.0.0.0", mask="0.0.0.0",
                nexthop="10.0.0.1",
            )],
        )
        rr = RenderResult(config_text="", features_rendered=["vlans"])
        v = CoverageValidator(
            src_domain=DeviceDomain.SWITCH,
            tgt_domain=DeviceDomain.SWITCH,
        )
        issues, ir_c, r_n = v.validate(ir=ir, render_result=rr)
        missing = [i for i in issues if "not in rendered_features" in i.message]
        assert len(missing) == 1
        assert "static_routes" in missing[0].message

    def test_ir_feature_presence_counts(self):
        ir = _make_ir(
            vlans=[IRVlan(IRType.VLAN, _span(), v) for v in [10, 20, 30]],
            lags=[IRLag(IRType.LAG, _span(), lag_id=1)],
        )
        v = CoverageValidator(
            src_domain=DeviceDomain.SWITCH,
            tgt_domain=DeviceDomain.SWITCH,
        )
        issues, ir_c, r_n = v.validate(ir=ir, render_result=None)
        assert ir_c.get("vlans") == 3
        assert ir_c.get("lags") == 1


class TestCoverageMappingSingleSource:
    """Phase 7B: Coverage mapping single source of truth verification."""

    def test_all_ir_to_feature_keys_have_feature_key(self):
        """Every key in _IR_TO_FEATURE must have a corresponding FeatureKey."""
        mapping = get_feature_mapping()
        for key in _IR_TO_FEATURE:
            assert key in mapping, (
                f"IR field '{key}' in _IR_TO_FEATURE has no FeatureKey in "
                f"_IR_FIELD_TO_FEATURE_KEY"
            )

    def test_all_feature_key_fields_have_ir_to_feature(self):
        """Every key in the FeatureKey mapping must be in _IR_TO_FEATURE."""
        mapping = get_feature_mapping()
        for key in mapping:
            assert key in _IR_TO_FEATURE, (
                f"FeatureKey field '{key}' has no entry in _IR_TO_FEATURE"
            )

    def test_mapping_returns_distinct_copy(self):
        """get_feature_mapping should not expose internal dict."""
        mapping = get_feature_mapping()
        mapping["_test"] = FeatureKey.VLAN  # type: ignore
        mapping2 = get_feature_mapping()
        assert "_test" not in mapping2
