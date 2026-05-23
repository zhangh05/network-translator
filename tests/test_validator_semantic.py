from __future__ import annotations

from core.domain import DeviceDomain
from core.ir_models import IRConfig, IRConfigMeta
from core.ir_models.base import SourceSpan
from core.ir_models.common import IRAcl, IRAclEntry, IRStaticRoute
from core.ir_models.enums import (
    ConversionStatus,
    IRFhrpProtocol,
    IRRiskLevel,
    IRType,
)
from core.ir_models.router import IROspf
from core.ir_models.switch import IRFhrp, IRLag, IRSvi, IRVlan
from core.renderer.base import RenderResult
from core.validator.semantic_validator import SemanticValidator


def _span():
    return SourceSpan(1, 1, ["line"])


def _make_ir(**overrides):
    meta = IRConfigMeta(
        source_vendor="h3c", target_vendor="cisco",
        source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
        source_platform="comware", target_platform="ios-xe",
    )
    return IRConfig(meta=meta, **overrides)


class TestSemanticValidatorSwitch:
    def setup_method(self):
        self.v = SemanticValidator(
            src_domain=DeviceDomain.SWITCH,
            tgt_domain=DeviceDomain.SWITCH,
        )

    def test_clean_ir_no_issues(self):
        ir = _make_ir()
        issues, metrics = self.v.validate(ir)
        assert len(issues) == 0
        assert "vlan_names" in metrics["passed_checks"]

    def test_metrics_separates_severity_buckets(self):
        ir = _make_ir(
            vlans=[IRVlan(IRType.VLAN, _span(), vid=10, name="MGMT")],
            svis=[IRSvi(IRType.SVI, _span(), vid=10, ip="10.0.0.1",
                        mask="255.255.255.0")],
        )
        issues, metrics = self.v.validate(ir)
        assert "vlan_names" in metrics["passed_checks"]
        assert "svi_ips" in metrics["passed_checks"]

    def test_acl_wildcard_is_info_not_failed(self):
        ir = _make_ir(
            acls=[IRAcl(IRType.ACL, _span(), acl_type="extended",
                        number=100, entries=[
                            IRAclEntry("permit", sequence=375, protocol="ip",
                                       src=None, dst=None),
                        ])],
        )
        issues, metrics = self.v.validate(ir)
        any_issues = [i for i in issues if "acl_wildcard" in i.field]
        assert len(any_issues) >= 1
        assert any_issues[0].severity == IRRiskLevel.LOW
        # LOW issues go to info_checks, not failed_checks
        assert "acl_entries" in metrics["info_checks"]
        assert "acl_entries" not in metrics["failed_checks"]

    def test_acl_order_high_goes_to_failed(self):
        ir = _make_ir(
            acls=[IRAcl(IRType.ACL, _span(), acl_type="extended",
                        number=100, entries=[
                            IRAclEntry("permit", sequence=20),
                            IRAclEntry("deny", sequence=10),
                        ])],
        )
        issues, metrics = self.v.validate(ir)
        order_issues = [i for i in issues if "acl_order" in i.field]
        assert len(order_issues) >= 1
        assert "acl_entries" in metrics["failed_checks"]

    def test_acl_binding_ref_not_found_uses_ir_level(self):
        ir = _make_ir(
            svis=[IRSvi(IRType.SVI, _span(), vid=107,
                        ip="10.0.0.1", mask="255.255.255.0",
                        acl_in="9999")],
            acls=[IRAcl(IRType.ACL, _span(), acl_type="extended",
                        number=3050, entries=[])],
        )
        issues, metrics = self.v.validate(ir)
        binding_issues = [i for i in issues if "acl_binding" in i.field]
        # ACL 9999 not defined in ir.acls
        assert len(binding_issues) >= 1
        assert "9999" in binding_issues[0].message

    def test_acl_binding_ref_found_no_issue(self):
        ir = _make_ir(
            svis=[IRSvi(IRType.SVI, _span(), vid=107,
                        ip="10.0.0.1", mask="255.255.255.0",
                        acl_in="3050")],
            acls=[IRAcl(IRType.ACL, _span(), acl_type="extended",
                        number=3050, entries=[])],
        )
        issues, metrics = self.v.validate(ir)
        binding_issues = [i for i in issues if "acl_binding" in i.field]
        assert len(binding_issues) == 0
        assert "acl_bindings" in metrics["passed_checks"]

    def test_svi_missing_ip_high(self):
        ir = _make_ir(
            svis=[IRSvi(IRType.SVI, _span(), vid=10,
                        ip=None, mask=None)],
        )
        issues, metrics = self.v.validate(ir)
        ip_issues = [i for i in issues if "svi_ip" in i.field]
        assert len(ip_issues) >= 1
        assert ip_issues[0].severity == IRRiskLevel.HIGH
        # HIGH goes to failed
        assert "svi_ips" in metrics["failed_checks"]

    def test_fhrp_approximated_medium(self):
        ir = _make_ir(
            svis=[IRSvi(IRType.SVI, _span(), vid=10,
                        fhrp=[IRFhrp(
                            IRType.FHRP, _span(),
                            protocol=IRFhrpProtocol.VRRP,
                            group_id=1, virtual_ip="10.0.0.1",
                            conversion_status=ConversionStatus.APPROXIMATED,
                            reason="Preempt behavior differs",
                        )])],
        )
        issues, metrics = self.v.validate(ir)
        fhrp_issues = [i for i in issues if "fhrp" in i.field]
        assert len(fhrp_issues) >= 1
        assert fhrp_issues[0].severity == IRRiskLevel.MEDIUM
        # MEDIUM goes to warning
        assert "fhrp" in metrics["warning_checks"]

    def test_static_route_unsupported_high(self):
        ir = _make_ir(
            static_routes=[IRStaticRoute(
                IRType.STATIC_ROUTE, _span(),
                prefix="0.0.0.0", mask="0.0.0.0",
                nexthop="10.0.0.1",
                conversion_status=ConversionStatus.UNSUPPORTED,
                reason="VRF context",
            )],
        )
        issues, metrics = self.v.validate(ir)
        route_issues = [i for i in issues if "static_route" in i.field]
        assert len(route_issues) >= 1
        assert route_issues[0].severity == IRRiskLevel.HIGH

    def test_lag_member_issue_detected(self):
        ir = _make_ir(
            lags=[IRLag(IRType.LAG, _span(), lag_id=1,
                        member_ports=["G0/1", "G0/2"],
                        conversion_status=ConversionStatus.APPROXIMATED,
                        reason="LACP mode changed")],
        )
        issues, metrics = self.v.validate(ir)
        lag_issues = [i for i in issues if "lag_member" in i.field]
        assert len(lag_issues) >= 1

    def test_no_cisco_cli_in_acl_binding_check(self):
        """Verify acl_binding check uses IR-level comparison, not Cisco CLI regex."""
        source = inspect.getsource(SemanticValidator._check_acl_bindings)
        assert "ip access-group" not in source
        assert "interface Vlan" not in source

    def test_passed_check_when_all_exact(self):
        ir = _make_ir(
            vlans=[IRVlan(IRType.VLAN, _span(), vid=10, name="MGMT")],
        )
        issues, metrics = self.v.validate(ir)
        assert "vlan_names" in metrics["passed_checks"]

    def test_multiple_checks_use_correct_buckets(self):
        ir = _make_ir(
            vlans=[IRVlan(IRType.VLAN, _span(), vid=10)],
            svis=[IRSvi(IRType.SVI, _span(), vid=10, ip="10.0.0.1",
                        mask="255.255.255.0")],
        )
        issues, metrics = self.v.validate(ir)
        # No issues — all passed
        assert len(metrics["passed_checks"]) >= 2
        assert len(metrics["failed_checks"]) == 0


class TestSemanticValidatorOspf:
    """Phase 7A: OSPF deep semantic checks."""

    def setup_method(self):
        self.v = SemanticValidator(
            src_domain=DeviceDomain.SWITCH,
            tgt_domain=DeviceDomain.SWITCH,
        )

    def test_ospf_exact_status_no_deep_data_manual_review(self):
        """OSPF with EXACT but no networks/areas/passive → manual_review."""
        ir = _make_ir(
            ospf=[IROspf(IRType.OSPF, _span(), process_id=1)],
        )
        issues, metrics = self.v.validate(ir)
        ospf_issues = [i for i in issues if "ospf" in i.field]
        assert len(ospf_issues) >= 1
        mr = [i for i in ospf_issues
              if i.category.value == "manual_review"]
        assert len(mr) >= 1
        assert "insufficient_info" in (mr[0].rule_id or "")

    def test_ospf_insufficient_info_has_evidence(self):
        ir = _make_ir(
            ospf=[IROspf(IRType.OSPF, _span(), process_id=1)],
        )
        issues, _ = self.v.validate(ir)
        ospf_issues = [i for i in issues if i.category.value == "manual_review"]
        if ospf_issues:
            assert ospf_issues[0].rule_id is not None
            assert ospf_issues[0].source_ref is not None

    def test_ospf_network_area_mismatch_detected(self):
        ir = _make_ir(
            ospf=[IROspf(
                IRType.OSPF, _span(), process_id=1,
                networks=[{"network": "10.0.0.0", "mask": "0.0.0.255",
                           "area": "99"}],
                areas=[{"area_id": "0", "type": "normal"}],
            )],
        )
        issues, metrics = self.v.validate(ir)
        mismatch = [i for i in issues
                    if i.rule_id == "ospf:network_area_mismatch"]
        assert len(mismatch) >= 1
        assert "99" in mismatch[0].message
        assert "0" in mismatch[0].message

    def test_ospf_area_type_conflict_detected(self):
        ir = _make_ir(
            ospf=[IROspf(
                IRType.OSPF, _span(), process_id=1,
                areas=[
                    {"area_id": "0", "type": "normal"},
                    {"area_id": "0", "type": "nssa"},
                ],
            )],
        )
        issues, _ = self.v.validate(ir)
        conflict = [i for i in issues
                    if i.rule_id == "ospf:area_type_conflict"]
        assert len(conflict) >= 1

    def test_ospf_full_data_passes(self):
        ir = _make_ir(
            ospf=[IROspf(
                IRType.OSPF, _span(), process_id=1,
                networks=[{"network": "10.0.0.0", "mask": "0.0.0.255",
                           "area": "0"}],
                areas=[{"area_id": "0", "type": "normal"}],
                passive_interfaces=["G0/1"],
            )],
        )
        issues, metrics = self.v.validate(ir)
        high_sev = [i for i in issues if i.severity in (
            IRRiskLevel.HIGH, IRRiskLevel.CRITICAL)]
        assert len(high_sev) == 0

    def test_ospf_non_exact_status_preserved(self):
        ir = _make_ir(
            ospf=[IROspf(
                IRType.OSPF, _span(), process_id=1,
                conversion_status=ConversionStatus.APPROXIMATED,
                reason="Process-id remapped",
            )],
        )
        issues, _ = self.v.validate(ir)
        conv = [i for i in issues
                if i.rule_id == "ospf:conversion_status"]
        assert len(conv) >= 1
        assert "approximated" in conv[0].message.lower()


import inspect


class TestSemanticValidatorRouter:
    def test_router_features_framework_no_cisco_cli(self):
        from core.ir_models.router import IRBgp, IRVrf
        ir = _make_ir(
            bgp=[IRBgp(IRType.BGP, _span(), asn=65001)],
            vrfs=[IRVrf(IRType.VRF, _span(), name="CUSTOMER_A")],
        )
        v = SemanticValidator(
            src_domain=DeviceDomain.ROUTER,
            tgt_domain=DeviceDomain.ROUTER,
        )
        issues, metrics = v.validate(ir)
        assert len(issues) == 0
        assert "router_semantic" in metrics["passed_checks"]


class TestSemanticValidatorFirewall:
    def test_firewall_features_framework_no_cisco_cli(self):
        from core.ir_models.firewall import IRZone, IRAddressObject
        ir = _make_ir(
            zones=[IRZone(IRType.ZONE, _span(), name="trust")],
            address_objects=[IRAddressObject(
                IRType.ADDRESS_OBJECT, _span(), name="SERVER1",
                ip="10.0.0.1")],
        )
        v = SemanticValidator(
            src_domain=DeviceDomain.FIREWALL,
            tgt_domain=DeviceDomain.FIREWALL,
        )
        issues, metrics = v.validate(ir)
        assert "firewall_semantic" in metrics["passed_checks"]
