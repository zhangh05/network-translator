from __future__ import annotations

from core.domain import DeviceDomain
from core.ir_models import IRConfig, IRConfigMeta
from core.ir_models.base import SourceSpan
from core.ir_models.common import IRAaa, IRAcl, IRAclEntry, IRManagement, IRStaticRoute
from core.ir_models.enums import ConversionStatus, IRFhrpProtocol, IRRiskLevel, IRType
from core.ir_models.switch import IRFhrp, IRSvi, IRVlan
from core.validator.conversion_validator import ConversionValidator


def _make_span(start=1, end=1):
    return SourceSpan(start_line=start, end_line=end, source_text=["config line"])


class TestConversionValidator:
    def test_empty_ir_no_issues(self):
        ir = IRConfig(meta=IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="comware", target_platform="ios-xe",
        ))
        v = ConversionValidator()
        issues = v.validate(ir)
        assert len(issues) == 0

    def test_all_exact_no_issues(self):
        ir = IRConfig(meta=IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="comware", target_platform="ios-xe",
        ))
        ir.vlans = [
            IRVlan(type=IRType.VLAN, source_span=_make_span(), vid=10),
            IRVlan(type=IRType.VLAN, source_span=_make_span(), vid=20),
        ]
        v = ConversionValidator()
        issues = v.validate(ir)
        assert len(issues) == 0

    def test_unsupported_object_generates_critical(self):
        ir = IRConfig(meta=IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="comware", target_platform="ios-xe",
        ))
        ir.static_routes = [
            IRStaticRoute(
                type=IRType.STATIC_ROUTE, source_span=_make_span(),
                prefix="0.0.0.0", mask="0.0.0.0", nexthop="10.0.0.1",
                conversion_status=ConversionStatus.UNSUPPORTED,
                reason="VRF context not supported",
            ),
        ]
        v = ConversionValidator()
        issues = v.validate(ir)
        assert len(issues) == 1
        assert issues[0].severity == IRRiskLevel.CRITICAL
        assert "unsupported" in issues[0].message

    def test_needs_review_generates_medium(self):
        ir = IRConfig(meta=IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="comware", target_platform="ios-xe",
        ))
        ir.aaa = IRAaa(
            type=IRType.AAA, source_span=_make_span(),
            conversion_status=ConversionStatus.NEEDS_REVIEW,
            reason="HWTACACS requires manual redesign",
        )
        v = ConversionValidator()
        issues = v.validate(ir)
        assert len(issues) == 1
        assert issues[0].severity == IRRiskLevel.MEDIUM
        assert "needs_review" in issues[0].message

    def test_approximated_generates_medium(self):
        ir = IRConfig(meta=IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="comware", target_platform="ios-xe",
        ))
        ir.vlans = [
            IRVlan(
                type=IRType.VLAN, source_span=_make_span(), vid=100,
                conversion_status=ConversionStatus.APPROXIMATED,
                reason="VLAN name truncated",
            ),
        ]
        v = ConversionValidator()
        issues = v.validate(ir)
        assert len(issues) == 1
        assert issues[0].severity == IRRiskLevel.MEDIUM
        assert "approximated" in issues[0].message

    def test_fhrp_sub_objects_checked(self):
        ir = IRConfig(meta=IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="comware", target_platform="ios-xe",
        ))
        ir.svis = [
            IRSvi(
                type=IRType.SVI, source_span=_make_span(), vid=10,
                conversion_status=ConversionStatus.EXACT,
                fhrp=[
                    IRFhrp(
                        type=IRType.FHRP, source_span=_make_span(),
                        protocol=IRFhrpProtocol.VRRP, group_id=1,
                        virtual_ip="10.0.0.1",
                        conversion_status=ConversionStatus.APPROXIMATED,
                        reason="Preempt behavior differs",
                    ),
                ],
            ),
        ]
        v = ConversionValidator()
        issues = v.validate(ir)
        assert len(issues) == 1
        assert "fhrp" in issues[0].field
        assert issues[0].severity == IRRiskLevel.MEDIUM

    def test_acl_entries_sub_objects_checked(self):
        ir = IRConfig(meta=IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="comware", target_platform="ios-xe",
        ))
        ir.acls = [
            IRAcl(
                type=IRType.ACL, source_span=_make_span(),
                acl_type="extended", number=3050,
                conversion_status=ConversionStatus.EXACT,
                entries=[
                    IRAclEntry(action="permit", sequence=10, protocol="ip",
                               src="10.0.0.0", src_wildcard="0.0.0.255"),
                ],
            ),
        ]
        v = ConversionValidator()
        issues = v.validate(ir)
        # Entries don't have conversion_status, so no issues
        assert len(issues) == 0

    def test_management_singleton_checked(self):
        ir = IRConfig(meta=IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="comware", target_platform="ios-xe",
        ))
        ir.management = IRManagement(
            type=IRType.MANAGEMENT, source_span=_make_span(),
            conversion_status=ConversionStatus.APPROXIMATED,
            reason="SNMPv3 to v2c downgrade",
        )
        v = ConversionValidator()
        issues = v.validate(ir)
        assert len(issues) == 1
        assert "management" in issues[0].field

    def test_unknown_blocks_scanned(self):
        ir = IRConfig(meta=IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="comware", target_platform="ios-xe",
        ))
        ir.unknown_blocks = [
            {"type": IRType.UNKNOWN, "source_text": "unknown command"},
        ]
        v = ConversionValidator()
        issues = v.validate(ir)
        assert len(issues) == 0
