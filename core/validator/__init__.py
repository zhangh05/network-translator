from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.domain import DeviceDomain, DomainProfile, FeatureKey
from core.ir_models import IRConfig
from core.ir_models.enums import IRRiskLevel
from core.renderer.base import RenderResult
from core.validator.base import (
    ValidationCategory,
    ValidationIssue,
    ValidationPolicy,
    ValidationReport,
)
from core.validator.capability_baseline import CapabilityBaseline
from core.validator.capability_gap_validator import CapabilityGapValidator
from core.validator.conversion_validator import ConversionValidator
from core.validator.coverage_validator import CoverageValidator
from core.validator.residue_validator import ResidueValidator
from core.validator.semantic_validator import SemanticValidator
from core.validator.syntax_validator import BasicSyntaxValidator
from core.vendor.base import VendorPlatformProfile

# Maps coverage IR field names (from _IR_TO_FEATURE keys) to FeatureKey enums
# for capability-aware post-processing of coverage issues.
_COVERAGE_FIELD_TO_FEATURE_KEY: dict[str, FeatureKey] = {
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

_COVERAGE_FIELD_RE = re.compile(r"^coverage:(.+)$")


@dataclass
class CompositeValidator:
    residue_validator: ResidueValidator | None = None
    conversion_validator: ConversionValidator | None = None
    capability_gap_validator: CapabilityGapValidator | None = None
    syntax_validator: BasicSyntaxValidator | None = None
    coverage_validator: CoverageValidator | None = None
    semantic_validator: SemanticValidator | None = None

    def validate(
        self,
        target_config: str,
        ir: IRConfig | None,
        render_result: RenderResult | None,
        src_profile: VendorPlatformProfile | None = None,
        tgt_profile: VendorPlatformProfile | None = None,
        src_domain: DeviceDomain | None = None,
        tgt_domain: DeviceDomain | None = None,
        policy: ValidationPolicy | None = None,
        domain_profile: DomainProfile | None = None,
    ) -> ValidationReport:
        all_issues: list[ValidationIssue] = []
        coverage_metrics: dict[str, int | float] = {}
        semantic_metrics: dict[str, list[str] | float] = {
            "checked": [], "passed": [], "failed": [],
        }

        # Derive capability baseline before sub-validators so it can guide
        # severity/category adjustments (deployable / manual_review / unsupported).
        baseline: CapabilityBaseline | None = None
        if src_profile is not None and tgt_profile is not None:
            src_caps = src_profile.capabilities.get(
                src_domain or src_profile.default_domain or DeviceDomain.SWITCH, {},
            )
            tgt_caps = tgt_profile.capabilities.get(
                tgt_domain or tgt_profile.default_domain or DeviceDomain.SWITCH, {},
            )
            baseline = CapabilityBaseline.derive(
                src_caps, tgt_caps,
                src_domain=src_domain, tgt_domain=tgt_domain,
            )

        if self.residue_validator is not None and target_config:
            all_issues.extend(self.residue_validator.validate(target_config))

        if self.conversion_validator is not None and ir is not None:
            all_issues.extend(self.conversion_validator.validate(ir))

        if self.capability_gap_validator is not None:
            all_issues.extend(self.capability_gap_validator.validate())

        if self.syntax_validator is not None and target_config:
            all_issues.extend(self.syntax_validator.validate(target_config))

        if self.coverage_validator is not None:
            cov_issues, ir_features, rendered_names = self.coverage_validator.validate(ir, render_result)
            ir_feature_count = sum(1 for v in ir_features.values() if v > 0)
            rendered_feature_count = len(rendered_names)
            coverage_metrics["ir_feature_count"] = ir_feature_count
            coverage_metrics["rendered_feature_count"] = rendered_feature_count
            if ir_feature_count > 0:
                coverage_metrics["coverage_verifiability_rate"] = round(
                    rendered_feature_count / ir_feature_count, 4,
                )
            # Capability-aware post-processing: coverage issues for features
            # that are manual_review or unsupported get adjusted category/severity.
            _adjust_coverage_against_baseline(cov_issues, baseline)
            all_issues.extend(cov_issues)

        if self.semantic_validator is not None and ir is not None:
            sem_issues, sem_metrics = self.semantic_validator.validate(ir, render_result)
            all_issues.extend(sem_issues)
            if baseline is not None:
                sem_metrics["semantic_verifiability_rate"] = round(baseline.verifiability_rate, 4)
            semantic_metrics = sem_metrics

        metadata: dict = {}
        if ir is None:
            metadata["structured_coverage_unavailable"] = True
            all_issues.append(ValidationIssue(
                category=ValidationCategory.MANUAL_REVIEW,
                severity=IRRiskLevel.HIGH,
                message="No structured IR: manual review required for full validation",
                field="manual_review_required",
            ))
        if render_result and render_result.features_skipped:
            metadata["features_skipped"] = render_result.features_skipped
            for feat in render_result.features_skipped:
                all_issues.append(ValidationIssue(
                    category=ValidationCategory.MANUAL_REVIEW,
                    severity=IRRiskLevel.MEDIUM,
                    message=f"Feature '{feat}': requires manual review",
                    field=f"manual_review:{feat}",
                ))

        if baseline is not None:
            metadata["capability_metrics"] = {
                "total_features_considered": baseline.total_features_considered,
                "auto_verifiable": baseline.auto_verifiable_count,
                "manual_review": baseline.manual_review_count,
                "unsupported": baseline.unsupported_count,
                "verifiability_rate": round(baseline.verifiability_rate, 4),
            }
            if baseline.unsupported_semantics:
                metadata["capability_gaps"] = sorted(
                    k.value for k in baseline.unsupported_semantics
                )
            if baseline.manual_review_semantics:
                metadata["capability_manual_review_items"] = {
                    reason: sorted(k.value for k in keys)
                    for reason, keys in sorted(baseline.manual_review_semantics.items())
                }

        if coverage_metrics:
            metadata["coverage_metrics"] = coverage_metrics
        if semantic_metrics:
            metadata["semantic_metrics"] = semantic_metrics

        if src_profile:
            metadata["source_profile"] = src_profile.key
        if tgt_profile:
            metadata["target_profile"] = tgt_profile.key
        if src_domain:
            metadata["source_domain"] = src_domain.value
        if tgt_domain:
            metadata["target_domain"] = tgt_domain.value

        return ValidationReport(
            issues=all_issues,
            metadata=metadata,
            policy=policy,
        )


def _adjust_coverage_against_baseline(
    issues: list[ValidationIssue],
    baseline: CapabilityBaseline | None,
) -> None:
    if baseline is None:
        return
    all_manual: set[FeatureKey] = set()
    for keys in baseline.manual_review_semantics.values():
        all_manual.update(keys)
    for issue in issues:
        if issue.category is not ValidationCategory.COVERAGE:
            continue
        if not issue.field:
            continue
        m = _COVERAGE_FIELD_RE.match(issue.field)
        if not m:
            continue
        fk = _COVERAGE_FIELD_TO_FEATURE_KEY.get(m.group(1))
        if fk is None:
            continue
        if fk in all_manual:
            issue.category = ValidationCategory.MANUAL_REVIEW
            issue.severity = IRRiskLevel.MEDIUM
            issue.rule_id = issue.rule_id or f"coverage:manual_review:{fk.value}"
            issue.source_ref = issue.source_ref or f"ir.{m.group(1)}"
            iss_sug = issue.suggestion or ""
            issue.suggestion = (
                f"{iss_sug} [capability: manual review required]".strip()
            )
        elif fk in baseline.unsupported_semantics:
            issue.rule_id = issue.rule_id or f"coverage:unsupported:{fk.value}"
            issue.source_ref = issue.source_ref or f"ir.{m.group(1)}"
            iss_sug = issue.suggestion or ""
            issue.suggestion = (
                f"{iss_sug} [capability: unsupported in target]".strip()
            )

__all__ = [
    "CompositeValidator",
    "ValidationCategory",
    "ValidationIssue",
    "ValidationPolicy",
    "ValidationReport",
    "ResidueValidator",
    "ConversionValidator",
    "CapabilityGapValidator",
    "BasicSyntaxValidator",
    "CoverageValidator",
    "SemanticValidator",
]
