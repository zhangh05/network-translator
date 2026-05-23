from __future__ import annotations

from core.ir_models.base import SourceSpan
from core.ir_models.enums import IRRiskLevel
from core.validator.base import (
    ValidationCategory,
    ValidationIssue,
    ValidationPolicy,
    ValidationReport,
)


class TestValidationCategory:
    def test_members(self):
        assert ValidationCategory.RESIDUE.value == "residue"
        assert ValidationCategory.CONVERSION.value == "conversion"
        assert ValidationCategory.CAPABILITY_GAP.value == "capability_gap"
        assert ValidationCategory.SYNTAX.value == "syntax"
        assert ValidationCategory.COVERAGE.value == "coverage"
        assert ValidationCategory.SEMANTIC.value == "semantic"
        assert ValidationCategory.MANUAL_REVIEW.value == "manual_review"


class TestValidationIssue:
    def test_basic_issue(self):
        issue = ValidationIssue(
            category=ValidationCategory.RESIDUE,
            severity=IRRiskLevel.HIGH,
            message="Residual found",
            field="residue:residual_syntax",
            line=42,
            source_text="undo vlan 10",
        )
        assert issue.category == ValidationCategory.RESIDUE
        assert issue.severity == IRRiskLevel.HIGH
        assert issue.line == 42

    def test_to_dict_minimal(self):
        issue = ValidationIssue(
            category=ValidationCategory.CONVERSION,
            severity=IRRiskLevel.MEDIUM,
            message="Needs review",
        )
        d = issue.to_dict()
        assert d["category"] == "conversion"
        assert d["severity"] == "medium"
        assert "line" not in d

    def test_to_dict_with_both_spans(self):
        src_span = SourceSpan(start_line=1, end_line=3, source_text=["src line"])
        tgt_span = SourceSpan(start_line=10, end_line=10, source_text=["tgt line"])
        issue = ValidationIssue(
            category=ValidationCategory.RESIDUE,
            severity=IRRiskLevel.CRITICAL,
            message="Bad pattern",
            field="residue:unsupported_feature",
            source_span=src_span,
            target_span=tgt_span,
            line=10,
            suggestion="Remove it",
            source_text="dangerous cmd",
        )
        d = issue.to_dict()
        assert d["source_span"]["start_line"] == 1
        assert d["target_span"]["start_line"] == 10
        assert d["suggestion"] == "Remove it"


class TestValidationReport:
    def test_empty_report(self):
        report = ValidationReport()
        assert len(report.issues) == 0
        assert report.summary() == {}
        assert report.deployable() is True

    def test_summary_counts(self):
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.RESIDUE, IRRiskLevel.HIGH, "h1"),
            ValidationIssue(ValidationCategory.RESIDUE, IRRiskLevel.HIGH, "h2"),
            ValidationIssue(ValidationCategory.CONVERSION, IRRiskLevel.MEDIUM, "m1"),
            ValidationIssue(ValidationCategory.SYNTAX, IRRiskLevel.LOW, "l1"),
        ])
        s = report.summary()
        assert s[IRRiskLevel.HIGH] == 2
        assert s[IRRiskLevel.MEDIUM] == 1
        assert s[IRRiskLevel.LOW] == 1

    def test_deployable_no_critical_or_high(self):
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.SYNTAX, IRRiskLevel.MEDIUM, "m1"),
        ])
        assert report.deployable() is True

    def test_not_deployable_with_critical(self):
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.RESIDUE, IRRiskLevel.CRITICAL, "c1"),
        ])
        assert report.deployable() is False

    def test_not_deployable_with_high(self):
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.RESIDUE, IRRiskLevel.HIGH, "h1"),
        ])
        assert report.deployable() is False

    def test_deployable_with_only_low(self):
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.SYNTAX, IRRiskLevel.LOW, "l1"),
        ])
        assert report.deployable() is True

    def test_by_category(self):
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.RESIDUE, IRRiskLevel.HIGH, "r1"),
            ValidationIssue(ValidationCategory.RESIDUE, IRRiskLevel.MEDIUM, "r2"),
            ValidationIssue(ValidationCategory.SYNTAX, IRRiskLevel.LOW, "s1"),
        ])
        cats = report.by_category()
        assert len(cats["residue"]) == 2
        assert len(cats["syntax"]) == 1

    def test_by_severity(self):
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.RESIDUE, IRRiskLevel.HIGH, "h1"),
        ])
        sevs = report.by_severity()
        assert len(sevs["high"]) == 1

    def test_to_dict_full(self):
        report = ValidationReport(
            issues=[
                ValidationIssue(ValidationCategory.RESIDUE, IRRiskLevel.HIGH, "test"),
            ],
            metadata={"source_profile": "h3c_comware", "target_profile": "cisco_ios_xe"},
        )
        d = report.to_dict()
        assert d["total_issues"] == 1
        assert d["deployable"] is False
        assert d["metadata"]["source_profile"] == "h3c_comware"


class TestValidationPolicy:
    def test_default_deploy_allowed(self):
        policy = ValidationPolicy()
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.SYNTAX, IRRiskLevel.LOW, "l1"),
        ])
        assert policy.allows_deploy(report) is True

    def test_blocks_critical_by_default(self):
        policy = ValidationPolicy()
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.RESIDUE, IRRiskLevel.CRITICAL, "c1"),
        ])
        assert policy.allows_deploy(report) is False

    def test_blocks_excessive_high(self):
        policy = ValidationPolicy(max_high=1)
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.RESIDUE, IRRiskLevel.HIGH, "h1"),
            ValidationIssue(ValidationCategory.RESIDUE, IRRiskLevel.HIGH, "h2"),
        ])
        assert policy.allows_deploy(report) is False

    def test_allows_within_high_threshold(self):
        policy = ValidationPolicy(max_high=3)
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.RESIDUE, IRRiskLevel.HIGH, "h1"),
        ])
        assert policy.allows_deploy(report) is True

    def test_categories_to_block(self):
        policy = ValidationPolicy(
            categories_to_block=[ValidationCategory.SYNTAX],
        )
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.SYNTAX, IRRiskLevel.LOW, "s1"),
        ])
        assert policy.allows_deploy(report) is False

    def test_forbid_unsupported_conversion(self):
        policy = ValidationPolicy(forbid_unsupported=True)
        report = ValidationReport(issues=[
            ValidationIssue(
                ValidationCategory.CONVERSION,
                IRRiskLevel.MEDIUM,
                "bgp: unsupported (BGP not available)",
            ),
        ])
        assert policy.allows_deploy(report) is False

    def test_allow_deploy_on_warnings_false(self):
        policy = ValidationPolicy(allow_deploy_on_warnings=False)
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.SYNTAX, IRRiskLevel.HIGH, "bad ip"),
        ])
        assert policy.allows_deploy(report) is False

    def test_allow_deploy_on_warnings_false_with_only_low(self):
        policy = ValidationPolicy(allow_deploy_on_warnings=False)
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.SYNTAX, IRRiskLevel.LOW, "minor"),
        ])
        assert policy.allows_deploy(report) is True


class TestValidationReportManualReview:
    def test_no_manual_review_by_default(self):
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.RESIDUE, IRRiskLevel.HIGH, "r1"),
        ])
        assert report.manual_review_required is False

    def test_manual_review_with_manual_review_category(self):
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.MANUAL_REVIEW, IRRiskLevel.HIGH, "needs man review"),
        ])
        assert report.manual_review_required is True

    def test_manual_review_true_and_deployable_true_both_possible(self):
        """MANUAL_REVIEW issues do not block deployability unless they are
        HIGH/CRITICAL severity (checked by deployable() logic).
        A MANUAL_REVIEW issue that's HIGH/CRITICAL blocks deploy.
        A MANUAL_REVIEW issue that's MEDIUM/LOW does not block deploy."""
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.MANUAL_REVIEW,
                            IRRiskLevel.MEDIUM, "check OSPF area"),
        ])
        assert report.manual_review_required is True
        assert report.deployable() is True

    def test_manual_review_in_to_dict(self):
        report = ValidationReport(issues=[
            ValidationIssue(ValidationCategory.MANUAL_REVIEW, IRRiskLevel.HIGH, "needs review"),
        ])
        d = report.to_dict()
        assert d["manual_review_required"] is True
