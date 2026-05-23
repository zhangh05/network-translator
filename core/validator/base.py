from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.ir_models.base import SourceSpan
from core.ir_models.enums import IRRiskLevel


class ValidationCategory(Enum):
    RESIDUE = "residue"
    CONVERSION = "conversion"
    CAPABILITY_GAP = "capability_gap"
    SYNTAX = "syntax"
    COVERAGE = "coverage"
    SEMANTIC = "semantic"
    MANUAL_REVIEW = "manual_review"


REPORT_SCHEMA_VERSION = "1.0"

SEVERITY_ORDER = {
    IRRiskLevel.CRITICAL: 0,
    IRRiskLevel.HIGH: 1,
    IRRiskLevel.MEDIUM: 2,
    IRRiskLevel.LOW: 3,
}


@dataclass
class ValidationIssue:
    category: ValidationCategory
    severity: IRRiskLevel
    message: str
    field: str | None = None
    target_span: SourceSpan | None = None
    source_span: SourceSpan | None = None
    line: int | None = None
    suggestion: str | None = None
    source_text: str | None = None
    rule_id: str | None = None
    source_ref: str | None = None
    rendered_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "category": self.category.value,
            "severity": self.severity.value,
            "message": self.message,
        }
        if self.field:
            d["field"] = self.field
        if self.line is not None:
            d["line"] = self.line
        if self.suggestion:
            d["suggestion"] = self.suggestion
        if self.source_text:
            d["source_text"] = self.source_text
        if self.rule_id:
            d["rule_id"] = self.rule_id
        if self.source_ref:
            d["source_ref"] = self.source_ref
        if self.rendered_ref:
            d["rendered_ref"] = self.rendered_ref
        if self.target_span:
            d["target_span"] = {
                "start_line": self.target_span.start_line,
                "end_line": self.target_span.end_line,
                "source_text": self.target_span.source_text,
            }
        if self.source_span:
            d["source_span"] = {
                "start_line": self.source_span.start_line,
                "end_line": self.source_span.end_line,
                "source_text": self.source_span.source_text,
            }
        return d


@dataclass
class ValidationPolicy:
    max_critical: int = 0
    max_high: int = 5
    max_medium: int = 20
    forbid_unsupported: bool = True
    require_full_coverage: bool = False
    categories_to_block: list[ValidationCategory] = field(default_factory=list)
    allow_deploy_on_warnings: bool = True

    def allows_deploy(self, report: ValidationReport) -> bool:
        counts = report.summary()
        if counts.get(IRRiskLevel.CRITICAL, 0) > self.max_critical:
            return False
        if counts.get(IRRiskLevel.HIGH, 0) > self.max_high:
            return False
        if counts.get(IRRiskLevel.MEDIUM, 0) > self.max_medium:
            return False
        if self.forbid_unsupported:
            for issue in report.issues:
                if issue.category == ValidationCategory.CONVERSION and \
                   "unsupported" in issue.message.lower():
                    return False
        if self.categories_to_block:
            for issue in report.issues:
                if issue.category in self.categories_to_block:
                    return False
        if self.require_full_coverage:
            coverage = report.metadata.get("coverage_ratio", 1.0)
            if coverage < 1.0:
                return False
        if not self.allow_deploy_on_warnings:
            for issue in report.issues:
                if issue.severity in (
                    IRRiskLevel.HIGH, IRRiskLevel.CRITICAL,
                ):
                    return False
        return True


@dataclass
class ValidationReport:
    issues: list[ValidationIssue] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    policy: ValidationPolicy | None = None

    def summary(self) -> dict[IRRiskLevel, int]:
        counts: dict[IRRiskLevel, int] = {}
        for issue in self.issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
        return counts

    def by_category(self) -> dict[str, list[ValidationIssue]]:
        result: dict[str, list[ValidationIssue]] = {}
        for issue in self.issues:
            result.setdefault(issue.category.value, []).append(issue)
        return result

    def by_severity(self) -> dict[str, list[ValidationIssue]]:
        result: dict[str, list[ValidationIssue]] = {}
        for issue in self.issues:
            result.setdefault(issue.severity.value, []).append(issue)
        return result

    @property
    def manual_review_required(self) -> bool:
        return any(
            issue.category == ValidationCategory.MANUAL_REVIEW
            for issue in self.issues
        )

    def deployable(self) -> bool:
        if self.policy:
            return self.policy.allows_deploy(self)
        return all(
            issue.severity not in (IRRiskLevel.CRITICAL, IRRiskLevel.HIGH)
            for issue in self.issues
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "summary": {
                k.value: v if isinstance(v, int) else v
                for k, v in self.summary().items()
            },
            "total_issues": len(self.issues),
            "deployable": self.deployable(),
            "manual_review_required": self.manual_review_required,
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": self.metadata,
        }
