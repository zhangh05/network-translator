"""Phase 7E: Multi-domain multi-vendor integration (anti-overfitting)."""
from __future__ import annotations

import json

from core.domain import DeviceDomain
from core.ir_models import IRConfig, IRConfigMeta
from core.ir_models.base import SourceSpan
from core.ir_models.common import IRAcl, IRAclEntry, IRStaticRoute
from core.ir_models.enums import ConversionStatus, IRType
from core.ir_models.firewall import IRAddressObject, IRSecurityPolicy, IRServiceObject, IRZone
from core.ir_models.router import IROspf
from core.renderer.base import RenderResult
from core.validator import CompositeValidator
from core.validator.base import ValidationCategory
from core.validator.coverage_validator import CoverageValidator
from core.validator.residue_validator import ResidueValidator
from core.validator.semantic_validator import SemanticValidator
from core.vendor import get_profile, init_profiles


def _span():
    return SourceSpan(1, 1, ["line"])


class TestIntegrationFirewallHuaweiUsgToHillstone:
    """FIREWALL chain: Huawei USG -> Hillstone StoneOS.

    Exercises: zones, address_objects, service_objects, security_policies.
    """

    def setup_method(self):
        init_profiles()
        self.usg = get_profile("huawei_usg")
        self.hillstone = get_profile("hillstone_stoneos")
        meta = IRConfigMeta(
            source_vendor="huawei", target_vendor="hillstone",
            source_domain=DeviceDomain.FIREWALL, target_domain=DeviceDomain.FIREWALL,
            source_platform="usg", target_platform="stoneos",
        )
        self.ir = IRConfig(
            meta=meta,
            zones=[
                IRZone(IRType.ZONE, _span(), name="trust",
                       members=["G0/1"]),
                IRZone(IRType.ZONE, _span(), name="untrust",
                       members=["G0/2"]),
            ],
            address_objects=[
                IRAddressObject(IRType.ADDRESS_OBJECT, _span(),
                                name="SERVER1", ip="10.0.0.1"),
                IRAddressObject(IRType.ADDRESS_OBJECT, _span(),
                                name="SERVER2", ip="10.0.0.2"),
            ],
            service_objects=[
                IRServiceObject(IRType.SERVICE_OBJECT, _span(),
                                name="HTTP", protocol="tcp", port="80"),
            ],
            security_policies=[
                IRSecurityPolicy(IRType.SECURITY_POLICY, _span(),
                                 name="allow-http", action="permit",
                                 from_zone="trust", to_zone="untrust",
                                 src_addresses=["SERVER1"],
                                 dst_addresses=["SERVER2"],
                                 services=["HTTP"]),
            ],
        )
        self.rr = RenderResult(
            config_text="!\nsecurity-policy rule name allow-http\n...\n",
            features_rendered=["zones", "address_objects",
                               "service_objects", "security_policies"],
            features_skipped=[],
        )
        self.cv = CompositeValidator(
            residue_validator=ResidueValidator(profile=self.hillstone),
            coverage_validator=CoverageValidator(
                src_domain=DeviceDomain.FIREWALL, tgt_domain=DeviceDomain.FIREWALL,
            ),
            semantic_validator=SemanticValidator(
                src_domain=DeviceDomain.FIREWALL, tgt_domain=DeviceDomain.FIREWALL,
            ),
        )
        self.report = self.cv.validate(
            target_config="hostname FW\nsecurity-policy rule name allow-http permit\n",
            ir=self.ir, render_result=self.rr,
            src_profile=self.usg, tgt_profile=self.hillstone,
            src_domain=DeviceDomain.FIREWALL, tgt_domain=DeviceDomain.FIREWALL,
        )

    def test_residue_no_high(self):
        cats = self.report.by_category()
        res = cats.get(ValidationCategory.RESIDUE.value, [])
        high_res = [i for i in res if i.severity.value == "high"]
        assert len(high_res) == 0

    def test_coverage_metrics(self):
        cm = self.report.metadata.get("coverage_metrics", {})
        assert cm.get("ir_feature_count") == 4
        assert cm.get("rendered_feature_count") == 4
        assert cm.get("coverage_verifiability_rate") == 1.0

    def test_semantic_metrics(self):
        sm = self.report.metadata.get("semantic_metrics", {})
        assert "firewall_semantic" in sm.get("passed_checks", [])
        assert "semantic_verifiability_rate" in sm
        assert sm["semantic_verifiability_rate"] >= 0

    def test_capability_metrics(self):
        cap = self.report.metadata.get("capability_metrics", {})
        assert cap.get("total_features_considered", 0) >= 3
        assert "verifiability_rate" in cap
        # overall index computed when coverage rate exists
        assert "overall_verifiability_index" in cap
        assert 0.0 <= cap["overall_verifiability_index"] <= 1.0

    def test_deployable(self):
        assert self.report.deployable() is True
        assert self.report.manual_review_required is False

    def test_schema_version(self):
        d = self.report.to_dict()
        assert d.get("schema_version") == "1.0"
        json.dumps(d)

    def test_capability_metrics_with_overall_index(self):
        cap = self.report.metadata.get("capability_metrics", {})
        # When coverage rate exists, overall index should be present
        cm = self.report.metadata.get("coverage_metrics", {})
        if cm.get("coverage_verifiability_rate") is not None:
            assert "overall_verifiability_index" in cap
            assert 0.0 <= cap["overall_verifiability_index"] <= 1.0


class TestIntegrationRouterOspfDeep:
    """ROUTER deep OSPF: H3C Comware -> Huawei VRP.

    OSPF IR includes networks, areas, passive_interfaces — should pass
    deep OSPF checks without insufficient_info manual_review.
    """

    def setup_method(self):
        init_profiles()
        self.h3c = get_profile("h3c_comware")
        self.huawei = get_profile("huawei_vrp")
        meta = IRConfigMeta(
            source_vendor="h3c", target_vendor="huawei",
            source_domain=DeviceDomain.ROUTER, target_domain=DeviceDomain.ROUTER,
            source_platform="comware", target_platform="vrp",
        )
        self.ir = IRConfig(
            meta=meta,
            ospf=[IROspf(
                IRType.OSPF, _span(), process_id=1,
                router_id="10.0.0.1",
                networks=[
                    {"network": "10.0.0.0", "mask": "0.0.0.255", "area": "0"},
                    {"network": "10.1.0.0", "mask": "0.0.0.255", "area": "1"},
                ],
                areas=[
                    {"area_id": "0", "type": "normal"},
                    {"area_id": "1", "type": "normal"},
                ],
                passive_interfaces=["G0/1", "G0/2"],
                reference_bandwidth=1000,
            )],
            static_routes=[IRStaticRoute(
                IRType.STATIC_ROUTE, _span(),
                prefix="0.0.0.0", mask="0.0.0.0", nexthop="192.168.1.1",
            )],
        )
        self.rr = RenderResult(
            config_text="!\nrouter ospf 1\n router-id 10.0.0.1\n!\n",
            features_rendered=["ospf", "static_routes"],
            features_skipped=[],
        )
        self.cv = CompositeValidator(
            residue_validator=ResidueValidator(profile=self.huawei),
            coverage_validator=CoverageValidator(
                src_domain=DeviceDomain.ROUTER, tgt_domain=DeviceDomain.ROUTER,
            ),
            semantic_validator=SemanticValidator(
                src_domain=DeviceDomain.ROUTER, tgt_domain=DeviceDomain.ROUTER,
            ),
        )
        self.report = self.cv.validate(
            target_config="hostname R1\n",
            ir=self.ir, render_result=self.rr,
            src_profile=self.h3c, tgt_profile=self.huawei,
            src_domain=DeviceDomain.ROUTER, tgt_domain=DeviceDomain.ROUTER,
        )

    def test_residue_detects_hostname_like_phase6d(self):
        """Huawei VRP detects 'hostname' as residual — same as Phase 6D
        TestIntegrationRouterCiscoToHuawei.test_residue_detects_hostname."""
        cats = self.report.by_category()
        res = cats.get(ValidationCategory.RESIDUE.value, [])
        hostname_res = [i for i in res if "hostname" in i.message]
        assert len(hostname_res) >= 1

    def test_coverage_all_rendered(self):
        cm = self.report.metadata.get("coverage_metrics", {})
        assert cm.get("coverage_verifiability_rate") == 1.0

    def test_ospf_no_insufficient_info(self):
        """Deep OSPF data should not trigger insufficient_info manual_review."""
        issues = self.report.issues
        insufficient = [i for i in issues
                        if i.rule_id == "ospf:insufficient_info"]
        assert len(insufficient) == 0

    def test_ospf_no_network_area_mismatch(self):
        mismatches = [i for i in self.report.issues
                      if i.rule_id == "ospf:network_area_mismatch"]
        assert len(mismatches) == 0

    def test_semantic_metrics(self):
        sm = self.report.metadata.get("semantic_metrics", {})
        assert "semantic_verifiability_rate" in sm
        assert sm["semantic_verifiability_rate"] >= 0

    def test_capability_metrics(self):
        cap = self.report.metadata.get("capability_metrics", {})
        assert cap.get("total_features_considered", 0) >= 3
        assert "verifiability_rate" in cap

    def test_schema_version(self):
        d = self.report.to_dict()
        assert d["schema_version"] == "1.0"

    def test_deployable_with_residue(self):
        """Huawei VRP residue (hostname → HIGH) blocks deployable.
        Expected: deployable=False, manual_review_required=False
        (residue is not MANUAL_REVIEW category)."""
        assert self.report.manual_review_required is False
        # HIGH residue blocks deployable without policy override
        assert self.report.deployable() is False


class TestIntegrationRouterOspfMismatch:
    """ROUTER OSPF mismatch: Cisco IOS-XE -> H3C Comware.

    OSPF with network area mismatch + only process_id (insufficient info)
    should produce manual_review issues.
    """

    def setup_method(self):
        init_profiles()
        self.cisco = get_profile("cisco_ios_xe")
        self.h3c = get_profile("h3c_comware")
        meta = IRConfigMeta(
            source_vendor="cisco", target_vendor="h3c",
            source_domain=DeviceDomain.ROUTER, target_domain=DeviceDomain.ROUTER,
            source_platform="ios-xe", target_platform="comware",
        )
        self.ir = IRConfig(
            meta=meta,
            ospf=[
                # Process 1: has data but network area mismatch
                IROspf(
                    IRType.OSPF, _span(), process_id=1,
                    networks=[{"network": "10.0.0.0", "mask": "0.0.0.255",
                               "area": "99"}],
                    areas=[{"area_id": "0", "type": "normal"}],
                ),
                # Process 2: only process_id -> insufficient info
                IROspf(
                    IRType.OSPF, _span(), process_id=2,
                ),
            ],
            bgp=[],
            vrfs=[],
            static_routes=[IRStaticRoute(
                IRType.STATIC_ROUTE, _span(),
                prefix="0.0.0.0", mask="0.0.0.0", nexthop="192.168.1.1",
            )],
        )
        self.rr = RenderResult(
            config_text="!\nrouter ospf 1\n!\n",
            features_rendered=["ospf", "static_routes"],
            features_skipped=[],
        )
        self.cv = CompositeValidator(
            residue_validator=ResidueValidator(profile=self.h3c),
            coverage_validator=CoverageValidator(
                src_domain=DeviceDomain.ROUTER, tgt_domain=DeviceDomain.ROUTER,
            ),
            semantic_validator=SemanticValidator(
                src_domain=DeviceDomain.ROUTER, tgt_domain=DeviceDomain.ROUTER,
            ),
        )
        self.report = self.cv.validate(
            target_config="hostname R2\n",
            ir=self.ir, render_result=self.rr,
            src_profile=self.cisco, tgt_profile=self.h3c,
            src_domain=DeviceDomain.ROUTER, tgt_domain=DeviceDomain.ROUTER,
        )

    def test_ospf_network_area_mismatch(self):
        mismatches = [i for i in self.report.issues
                      if i.rule_id == "ospf:network_area_mismatch"]
        assert len(mismatches) >= 1

    def test_ospf_insufficient_info_manual_review(self):
        insufficient = [i for i in self.report.issues
                        if i.rule_id == "ospf:insufficient_info"]
        assert len(insufficient) >= 1

    def test_ospf_mismatch_evidence_fields(self):
        mismatches = [i for i in self.report.issues
                      if i.rule_id == "ospf:network_area_mismatch"]
        if mismatches:
            assert mismatches[0].source_ref is not None
            assert mismatches[0].rule_id is not None

    def test_coverage_metrics(self):
        cm = self.report.metadata.get("coverage_metrics", {})
        assert cm.get("coverage_verifiability_rate", 0) >= 0.5

    def test_schema_version(self):
        d = self.report.to_dict()
        assert d["schema_version"] == "1.0"
        json.dumps(d)

    def test_deployable_with_manual_review(self):
        """OSPF manual_review exists (insufficient_info MEDIUM) but HIGH
        residue + HIGH OSPF mismatch block deployable."""
        assert self.report.manual_review_required is True
        # HIGH severity issues (residue + ospf mismatch) block deployable
        assert self.report.deployable() is False


# Assertion data tables for machine-readable output

PHASE_7E_ASSERTION_TABLES: dict[str, list[dict[str, str | int | float | bool]]] = {
    "firewall_huawei_usg_to_hillstone": [
        {"assertion": "residue_high_count", "expected": 0, "actual": "computed_at_runtime"},
        {"assertion": "coverage_verifiability_rate", "expected": 1.0, "actual": "computed_at_runtime"},
        {"assertion": "ir_feature_count", "expected": 4, "actual": "computed_at_runtime"},
        {"assertion": "rendered_feature_count", "expected": 4, "actual": "computed_at_runtime"},
        {"assertion": "firewall_semantic_passed", "expected": True, "actual": "computed_at_runtime"},
        {"assertion": "deployable", "expected": True, "actual": "computed_at_runtime"},
        {"assertion": "manual_review_required", "expected": False, "actual": "computed_at_runtime"},
        {"assertion": "schema_version", "expected": "1.0", "actual": "computed_at_runtime"},
    ],
    "router_h3c_to_huawei_ospf_deep": [
        {"assertion": "residue_count", "expected": 0, "actual": "computed_at_runtime"},
        {"assertion": "coverage_verifiability_rate", "expected": 1.0, "actual": "computed_at_runtime"},
        {"assertion": "ospf_insufficient_info_count", "expected": 0, "actual": "computed_at_runtime"},
        {"assertion": "ospf_network_area_mismatch_count", "expected": 0, "actual": "computed_at_runtime"},
        {"assertion": "deployable", "expected": True, "actual": "computed_at_runtime"},
        {"assertion": "schema_version", "expected": "1.0", "actual": "computed_at_runtime"},
    ],
    "router_cisco_to_h3c_ospf_mismatch": [
        {"assertion": "ospf_network_area_mismatch_count", "expected": 1, "actual": "computed_at_runtime"},
        {"assertion": "ospf_insufficient_info_count", "expected": 1, "actual": "computed_at_runtime"},
        {"assertion": "manual_review_required", "expected": True, "actual": "computed_at_runtime"},
        {"assertion": "deployable", "expected": True, "actual": "computed_at_runtime"},
        {"assertion": "schema_version", "expected": "1.0", "actual": "computed_at_runtime"},
    ],
}
