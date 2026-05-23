from __future__ import annotations

from dataclasses import dataclass, field

from core.domain import DeviceDomain, DomainProfile, FeatureKey
from core.ir_models import IRConfig
from core.ir_models.enums import IRRiskLevel
from core.renderer.base import RenderResult
from core.validator.base import ValidationCategory, ValidationIssue


_IR_TO_FEATURE: dict[str, str | list[str]] = {
    "vlans": "vlans",
    "svis": "svis",
    "interfaces": "interfaces",
    "lags": ["lags", "lacp"],
    "static_routes": "static_routes",
    "ospf": "ospf",
    "bgp": "bgp",
    "acls": "acls",
    "vrfs": "vrfs",
    "pbrs": "pbrs",
    "nat_rules": "nat_rules",
    "ipsec_vpns": "ipsec_vpns",
    "zones": "zones",
    "address_objects": "address_objects",
    "service_objects": "service_objects",
    "security_policies": "security_policies",
    "management": "management",
    "aaa": "aaa",
    "stp": "stp",
}

# Single source of truth: maps IR field names → FeatureKey for capability-aware
# coverage post-processing. Must stay in sync with _IR_TO_FEATURE keys.
_IR_FIELD_TO_FEATURE_KEY: dict[str, FeatureKey] = {
    "vlans": FeatureKey.VLAN,
    "svis": FeatureKey.SVI,
    "interfaces": FeatureKey.INTERFACE,
    "lags": FeatureKey.LACP,
    "static_routes": FeatureKey.STATIC_ROUTE,
    "ospf": FeatureKey.OSPF,
    "bgp": FeatureKey.BGP,
    "acls": FeatureKey.ACL,
    "vrfs": FeatureKey.VRF,
    "pbrs": FeatureKey.PBR,
    "nat_rules": FeatureKey.NAT,
    "ipsec_vpns": FeatureKey.IPSEC_VPN,
    "zones": FeatureKey.ZONE,
    "address_objects": FeatureKey.ADDRESS_OBJECT,
    "service_objects": FeatureKey.SERVICE_OBJECT,
    "security_policies": FeatureKey.SECURITY_POLICY,
    "management": FeatureKey.MANAGEMENT,
    "aaa": FeatureKey.AAA,
    "stp": FeatureKey.STP,
}


def get_feature_mapping() -> dict[str, FeatureKey]:
    """Return the IR field name → FeatureKey mapping (single source of truth)."""
    return dict(_IR_FIELD_TO_FEATURE_KEY)


def _ir_feature_presence(ir: IRConfig) -> dict[str, int]:
    counts: dict[str, int] = {}
    for ir_field in _IR_TO_FEATURE:
        val = getattr(ir, ir_field, None)
        if isinstance(val, list):
            counts[ir_field] = len(val)
        elif val is not None:
            counts[ir_field] = 1
        else:
            counts[ir_field] = 0
    return counts


@dataclass
class CoverageValidator:
    src_domain: DeviceDomain
    tgt_domain: DeviceDomain
    domain_profile: DomainProfile | None = None
    thresholds: dict[str, float] | None = None

    def __post_init__(self):
        if self.thresholds is None:
            if self.domain_profile is not None:
                self.thresholds = self.domain_profile.coverage_thresholds
            else:
                self.thresholds = {}

    def validate(
        self,
        ir: IRConfig | None,
        render_result: RenderResult | None,
    ) -> tuple[list[ValidationIssue], dict[str, int], list[str]]:
        issues: list[ValidationIssue] = []
        ir_features: dict[str, int] = {}
        rendered_feature_names: list[str] = []
        skipped_feature_names: list[str] = []

        if ir is not None:
            ir_features = _ir_feature_presence(ir)

        if render_result is not None:
            rendered_feature_names = render_result.features_rendered
            skipped_feature_names = render_result.features_skipped

        if render_result is None or ir is None:
            return issues, ir_features, rendered_feature_names

        for feat_name, ir_count in sorted(ir_features.items()):
            if ir_count == 0:
                continue

            expected = _IR_TO_FEATURE.get(feat_name, feat_name)
            if isinstance(expected, list):
                rendered = any(e in rendered_feature_names for e in expected)
            else:
                rendered = expected in rendered_feature_names

            if not rendered:
                # Don't flag features that were intentionally skipped
                skipped = False
                if isinstance(expected, list):
                    skipped = any(e in skipped_feature_names for e in expected)
                else:
                    skipped = expected in skipped_feature_names
                if skipped:
                    continue

                severity = IRRiskLevel.CRITICAL if ir_count >= 5 else IRRiskLevel.HIGH
                issues.append(ValidationIssue(
                    category=ValidationCategory.COVERAGE,
                    severity=severity,
                    message=f"{feat_name}: {ir_count} instance(s) in IR but "
                            f"not in rendered_features",
                    field=f"coverage:{feat_name}",
                ))

        return issues, ir_features, rendered_feature_names
