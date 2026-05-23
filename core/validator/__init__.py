from __future__ import annotations

from dataclasses import dataclass, field

from core.domain import DeviceDomain, DomainProfile
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
        coverage_metrics: dict[str, int] = {}
        semantic_metrics: dict[str, list[str]] = {"checked": [], "passed": [], "failed": []}

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
            all_issues.extend(cov_issues)
            coverage_metrics["ir_feature_count"] = sum(1 for v in ir_features.values() if v > 0)
            coverage_metrics["rendered_feature_count"] = len(rendered_names)

        if self.semantic_validator is not None and ir is not None:
            sem_issues, sem_metrics = self.semantic_validator.validate(ir, render_result)
            all_issues.extend(sem_issues)
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

        if src_profile is not None and tgt_profile is not None:
            src_caps = src_profile.capabilities.get(src_domain or src_profile.default_domain or DeviceDomain.SWITCH, {})
            tgt_caps = tgt_profile.capabilities.get(tgt_domain or tgt_profile.default_domain or DeviceDomain.SWITCH, {})
            baseline = CapabilityBaseline.derive(
                src_caps, tgt_caps,
                src_domain=src_domain, tgt_domain=tgt_domain,
            )
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
