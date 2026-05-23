"""Phase 6D: Multi-sample integration verification (anti-overfitting)."""
from __future__ import annotations

import json
import sys

from core.domain import DeviceDomain
from core.ir_models import IRConfig, IRConfigMeta
from core.ir_models.enums import ConversionStatus, IRRiskLevel, IRType
from core.ir_models.switch import IRSvi, IRVlan, IRLag
from core.ir_models.common import IRAcl, IRAclEntry, IRStaticRoute
from core.ir_models.router import IRBgp, IRVrf
from core.ir_models.base import SourceSpan
from core.renderer.base import RenderResult
from core.validator import CompositeValidator
from core.validator.base import ValidationCategory
from core.validator.coverage_validator import CoverageValidator
from core.validator.semantic_validator import SemanticValidator
from core.validator.conversion_validator import ConversionValidator
from core.validator.residue_validator import ResidueValidator
from core.vendor import get_profile, init_profiles


def _span():
    return SourceSpan(1, 1, ["line"])


def _fmt(s):
    """Format a summary dict to string."""
    return ", ".join(f"{k.value}={v}" for k, v in sorted(s.items(), key=lambda x: x[0].value))


class TestIntegrationSwitchH3CtoCisco:
    """Main test_config chain: H3C Comware → Cisco IOS-XE SWITCH."""

    def setup_method(self):
        init_profiles()
        self.h3c = get_profile("h3c_comware")
        self.cisco = get_profile("cisco_ios_xe")
        meta = IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="comware", target_platform="ios-xe",
        )
        self.ir = IRConfig(
            meta=meta,
            vlans=[IRVlan(IRType.VLAN, _span(), vid=10),
                   IRVlan(IRType.VLAN, _span(), vid=20, name="MGMT")],
            svis=[IRSvi(IRType.SVI, _span(), vid=10,
                        ip="10.0.0.1", mask="255.255.255.0"),
                  IRSvi(IRType.SVI, _span(), vid=20,
                        ip="10.0.0.2", mask="255.255.255.0",
                        acl_in="3050")],
            acls=[IRAcl(IRType.ACL, _span(), acl_type="extended",
                        number=3050, entries=[
                            IRAclEntry("permit", sequence=5, protocol="tcp",
                                       src="any", dst="any"),
                            IRAclEntry("permit", sequence=10, protocol="ip")]),
                  IRAcl(IRType.ACL, _span(), acl_type="basic",
                        number=2000, entries=[
                            IRAclEntry("permit", sequence=5, protocol="ip")])],
            static_routes=[IRStaticRoute(
                IRType.STATIC_ROUTE, _span(),
                prefix="0.0.0.0", mask="0.0.0.0", nexthop="10.0.0.254"),
                IRStaticRoute(
                IRType.STATIC_ROUTE, _span(),
                prefix="10.1.0.0", mask="255.255.0.0", nexthop="10.0.0.253")],
        )
        self.rr = RenderResult(
            config_text="!\ninterface Vlan10\n ip address 10.0.0.1 255.255.255.0\n!\n",
            features_rendered=["vlans", "svis", "acls", "static_routes"],
            features_skipped=[],
        )
        self.cv = CompositeValidator(
            residue_validator=ResidueValidator(profile=self.cisco),
            conversion_validator=ConversionValidator(),
            semantic_validator=SemanticValidator(
                src_domain=DeviceDomain.SWITCH, tgt_domain=DeviceDomain.SWITCH,
            ),
            coverage_validator=CoverageValidator(
                src_domain=DeviceDomain.SWITCH, tgt_domain=DeviceDomain.SWITCH,
            ),
        )
        self.report = self.cv.validate(
            target_config="hostname Test\n",
            ir=self.ir, render_result=self.rr,
            src_profile=self.h3c, tgt_profile=self.cisco,
            src_domain=DeviceDomain.SWITCH, tgt_domain=DeviceDomain.SWITCH,
        )

    def test_residue_no_high(self):
        cats = self.report.by_category()
        res = cats.get(ValidationCategory.RESIDUE.value, [])
        assert len(res) == 0

    def test_coverage_metrics(self):
        cm = self.report.metadata.get("coverage_metrics", {})
        assert cm.get("ir_feature_count") == 4
        assert cm.get("rendered_feature_count") == 4
        assert cm.get("coverage_verifiability_rate") == 1.0

    def test_semantic_metrics(self):
        sm = self.report.metadata.get("semantic_metrics", {})
        # ACL 3050 has permit tcp any any, ACL 2000 has permit ip -> wildcard LOW
        assert "acl_entries" in sm.get("info_checks", [])
        # All other checks pass
        assert "vlan_names" in sm.get("passed_checks", [])
        assert "svi_ips" in sm.get("passed_checks", [])
        assert "static_routes" in sm.get("passed_checks", [])
        assert "semantic_verifiability_rate" in sm
        assert sm["semantic_verifiability_rate"] > 0

    def test_capability_metrics(self):
        cap = self.report.metadata.get("capability_metrics", {})
        assert cap.get("total_features_considered", 0) >= 10
        assert cap.get("auto_verifiable", 0) >= 5
        assert cap.get("verifiability_rate", 0) > 0

    def test_deployable_and_manual_review(self):
        assert self.report.deployable() is True
        # No MANUAL_REVIEW issues in clean round-trip
        assert self.report.manual_review_required is False

    def test_schema_version_in_to_dict(self):
        d = self.report.to_dict()
        assert d.get("schema_version") == "1.0"
        assert "issues" in d
        assert "summary" in d
        assert "metadata" in d


class TestIntegrationRouterCiscoToHuawei:
    """ROUTER domain: Cisco IOS-XE → Huawei VRP."""

    def setup_method(self):
        init_profiles()
        self.cisco = get_profile("cisco_ios_xe")
        self.huawei = get_profile("huawei_vrp")
        meta = IRConfigMeta(
            source_vendor="cisco", target_vendor="huawei",
            source_domain=DeviceDomain.ROUTER, target_domain=DeviceDomain.ROUTER,
            source_platform="ios-xe", target_platform="vrp",
        )
        self.ir = IRConfig(
            meta=meta,
            static_routes=[IRStaticRoute(
                IRType.STATIC_ROUTE, _span(),
                prefix="0.0.0.0", mask="0.0.0.0", nexthop="192.168.1.1")],
            bgp=[IRBgp(IRType.BGP, _span(), asn=65001)],
            vrfs=[IRVrf(IRType.VRF, _span(), name="CUSTOMER_A", rd="65001:100")],
        )
        self.rr = RenderResult(
            config_text="!\nip route-static 0.0.0.0 0 192.168.1.1\n!\n",
            features_rendered=["static_routes"],
            features_skipped=[],
        )
        self.cv = CompositeValidator(
            residue_validator=ResidueValidator(profile=self.huawei),
            conversion_validator=ConversionValidator(),
            semantic_validator=SemanticValidator(
                src_domain=DeviceDomain.ROUTER, tgt_domain=DeviceDomain.ROUTER,
            ),
            coverage_validator=CoverageValidator(
                src_domain=DeviceDomain.ROUTER, tgt_domain=DeviceDomain.ROUTER,
            ),
        )
        self.report = self.cv.validate(
            target_config="hostname Test\n",
            ir=self.ir, render_result=self.rr,
            src_profile=self.cisco, tgt_profile=self.huawei,
            src_domain=DeviceDomain.ROUTER, tgt_domain=DeviceDomain.ROUTER,
        )

    def test_residue_detects_hostname(self):
        """Residue should detect 'hostname' — Huawei VRP uses 'sysname'.
        This is a legitimate HIGH residual: 'hostname' would be an executable
        command, not a comment."""
        cats = self.report.by_category()
        res = cats.get(ValidationCategory.RESIDUE.value, [])
        assert len(res) >= 1
        hostname_res = [i for i in res if "hostname" in i.message]
        assert len(hostname_res) >= 1

    def test_coverage_gap_detected(self):
        """BGP and VRF not rendered -> coverage issues (should be downgraded
        to MANUAL_REVIEW via capability-aware post-processing since they may
        be in manual_review baseline)."""
        cats = self.report.by_category()
        cv = cats.get(ValidationCategory.COVERAGE.value, [])
        mr = cats.get(ValidationCategory.MANUAL_REVIEW.value, [])
        has_coverage_or_manual = len(cv) + len(mr) > 0
        assert has_coverage_or_manual

    def test_capability_metrics_set(self):
        cap = self.report.metadata.get("capability_metrics", {})
        assert cap.get("total_features_considered", 0) >= 3
        assert "verifiability_rate" in cap

    def test_semantic_verifiability_rate(self):
        sm = self.report.metadata.get("semantic_metrics", {})
        assert "semantic_verifiability_rate" in sm
        assert sm["semantic_verifiability_rate"] >= 0

    def test_schema_version(self):
        d = self.report.to_dict()
        assert d.get("schema_version") == "1.0"

    def test_evidence_fields_in_issues(self):
        """Issues should carry field and/or suggestion for traceability."""
        has_field = any(i.field for i in self.report.issues)
        assert has_field


class TestIntegrationSwitchHuaweiToCisco:
    """SWITCH domain: Huawei VRP → Cisco IOS-XE (different vendor pair)."""

    def setup_method(self):
        init_profiles()
        self.huawei = get_profile("huawei_vrp")
        self.cisco = get_profile("cisco_ios_xe")
        meta = IRConfigMeta(
            source_vendor="huawei", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="vrp", target_platform="ios-xe",
        )
        self.ir = IRConfig(
            meta=meta,
            vlans=[IRVlan(IRType.VLAN, _span(), vid=100, name="USERS")],
            svis=[IRSvi(IRType.SVI, _span(), vid=100,
                        ip="192.168.1.254", mask="255.255.255.0")],
            acls=[IRAcl(IRType.ACL, _span(), acl_type="basic",
                        number=3000, entries=[
                            IRAclEntry("permit", sequence=5, protocol="ip")])],
            static_routes=[IRStaticRoute(
                IRType.STATIC_ROUTE, _span(),
                prefix="0.0.0.0", mask="0.0.0.0", nexthop="192.168.1.1")],
        )
        self.rr = RenderResult(
            config_text="!\ninterface Vlan100\n ip address 192.168.1.254 255.255.255.0\n!\n",
            features_rendered=["vlans", "svis", "acls", "static_routes"],
            features_skipped=[],
        )
        self.cv = CompositeValidator(
            residue_validator=ResidueValidator(profile=self.cisco),
            conversion_validator=ConversionValidator(),
            semantic_validator=SemanticValidator(
                src_domain=DeviceDomain.SWITCH, tgt_domain=DeviceDomain.SWITCH,
            ),
            coverage_validator=CoverageValidator(
                src_domain=DeviceDomain.SWITCH, tgt_domain=DeviceDomain.SWITCH,
            ),
        )
        self.report = self.cv.validate(
            target_config="hostname Test\n",
            ir=self.ir, render_result=self.rr,
            src_profile=self.huawei, tgt_profile=self.cisco,
            src_domain=DeviceDomain.SWITCH, tgt_domain=DeviceDomain.SWITCH,
        )

    def test_residue_clean(self):
        cats = self.report.by_category()
        res = cats.get(ValidationCategory.RESIDUE.value, [])
        assert len(res) == 0

    def test_coverage_all_rendered(self):
        cm = self.report.metadata.get("coverage_metrics", {})
        assert cm.get("coverage_verifiability_rate") == 1.0

    def test_semantic_metrics_exist(self):
        sm = self.report.metadata.get("semantic_metrics", {})
        assert len(sm.get("checked", [])) > 0
        assert "semantic_verifiability_rate" in sm

    def test_capability_metrics(self):
        cap = self.report.metadata.get("capability_metrics", {})
        assert "verifiability_rate" in cap
        assert cap.get("total_features_considered", 0) >= 5

    def test_deployable(self):
        # Should be deployable (only LOW semantic issues for permit ip any any)
        assert self.report.deployable() is True
        assert self.report.manual_review_required is False
        assert len(self.report.issues) == 1  # only permit ip any any LOW

    def test_to_dict_serializable(self):
        d = self.report.to_dict()
        json.dumps(d)
        assert d["schema_version"] == "1.0"
