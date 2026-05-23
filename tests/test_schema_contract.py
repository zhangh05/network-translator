"""Phase 7C: Report & issue schema contract tests."""

from core.ir_models.enums import IRRiskLevel
from core.validator.base import (
    REPORT_SCHEMA_VERSION,
    ValidationCategory,
    ValidationIssue,
    ValidationPolicy,
    ValidationReport,
)


class TestSchemaContractToDict:
    """to_dict() structure stability contract."""

    def test_schema_version_present_and_string(self):
        r = ValidationReport()
        d = r.to_dict()
        assert "schema_version" in d
        assert isinstance(d["schema_version"], str)
        assert d["schema_version"] == "1.0"

    def test_schema_version_constant_accessible(self):
        assert REPORT_SCHEMA_VERSION == "1.0"

    def test_summary_present(self):
        r = ValidationReport()
        d = r.to_dict()
        assert "summary" in d
        assert isinstance(d["summary"], dict)

    def test_total_issues_is_int(self):
        r = ValidationReport(
            issues=[ValidationIssue(
                category=ValidationCategory.SEMANTIC,
                severity=IRRiskLevel.HIGH,
                message="test",
            )],
        )
        d = r.to_dict()
        assert d["total_issues"] == 1
        assert isinstance(d["total_issues"], int)

    def test_deployable_required_fields(self):
        r = ValidationReport()
        d = r.to_dict()
        assert "deployable" in d
        assert isinstance(d["deployable"], bool)
        assert "manual_review_required" in d
        assert isinstance(d["manual_review_required"], bool)

    def test_issues_is_list(self):
        r = ValidationReport(
            issues=[ValidationIssue(
                category=ValidationCategory.SEMANTIC,
                severity=IRRiskLevel.LOW,
                message="info issue",
            )],
        )
        d = r.to_dict()
        assert "issues" in d
        assert isinstance(d["issues"], list)
        assert len(d["issues"]) == 1

    def test_issue_field_lowercase_severity(self):
        """Severity in to_dict must be lowercase enum value, not uppercase."""
        issue = ValidationIssue(
            category=ValidationCategory.SEMANTIC,
            severity=IRRiskLevel.MEDIUM,
            message="test",
        )
        d = issue.to_dict()
        assert d["severity"] == "medium"

    def test_issue_contains_category_severity_message(self):
        issue = ValidationIssue(
            category=ValidationCategory.COVERAGE,
            severity=IRRiskLevel.HIGH,
            message="coverage gap",
        )
        d = issue.to_dict()
        assert d["category"] == "coverage"
        assert d["severity"] == "high"
        assert d["message"] == "coverage gap"

    def test_issue_optional_fields_omitted_when_none(self):
        issue = ValidationIssue(
            category=ValidationCategory.SEMANTIC,
            severity=IRRiskLevel.LOW,
            message="test",
        )
        d = issue.to_dict()
        assert "field" not in d
        assert "line" not in d
        assert "suggestion" not in d
        assert "rule_id" not in d
        assert "source_ref" not in d

    def test_issue_evidence_fields_serialized_when_set(self):
        issue = ValidationIssue(
            category=ValidationCategory.MANUAL_REVIEW,
            severity=IRRiskLevel.MEDIUM,
            message="manual review needed",
            rule_id="test:rule",
            source_ref="ir.vlans",
            rendered_ref="rendered:vlans",
        )
        d = issue.to_dict()
        assert d["rule_id"] == "test:rule"
        assert d["source_ref"] == "ir.vlans"
        assert d["rendered_ref"] == "rendered:vlans"

    def test_metadata_is_dict(self):
        r = ValidationReport(metadata={"key": "value"})
        d = r.to_dict()
        assert "metadata" in d
        assert d["metadata"]["key"] == "value"

    def test_metadata_custom_field_not_overwritten(self):
        r = ValidationReport(
            issues=[],
            metadata={"custom_flag": True},
        )
        d = r.to_dict()
        assert d["metadata"].get("custom_flag") is True


class TestSchemaBackwardCompatibility:
    """Old consumer simulation: critical fields must exist."""

    def test_legacy_consumer_can_read_basic_fields(self):
        issue = ValidationIssue(
            category=ValidationCategory.RESIDUE,
            severity=IRRiskLevel.HIGH,
            message="legacy check",
            field="residue:hostname",
        )
        d = issue.to_dict()
        # Old consumers expect these base fields:
        assert "category" in d
        assert "severity" in d
        assert "message" in d
        # Old consumers should not crash if field is absent
        assert d.get("field") == "residue:hostname"
        # New fields are additive:
        assert d.get("rule_id") is None  # type: ignore[comparison-overlap]
        # (None is not serialized, so 'rule_id' won't appear in dict)

    def test_legacy_report_summary_shape(self):
        r = ValidationReport(
            issues=[
                ValidationIssue(
                    category=ValidationCategory.RESIDUE,
                    severity=IRRiskLevel.HIGH,
                    message="r1",
                ),
                ValidationIssue(
                    category=ValidationCategory.SEMANTIC,
                    severity=IRRiskLevel.LOW,
                    message="s1",
                ),
            ],
        )
        d = r.to_dict()
        s = d["summary"]
        assert isinstance(s, dict)
        # Severity values as lowercase enum value keys:
        assert "high" in s
        assert s["high"] == 1
        assert "low" in s
        assert s["low"] == 1

    def test_deployable_default_without_policy(self):
        r = ValidationReport(
            issues=[ValidationIssue(
                category=ValidationCategory.SEMANTIC,
                severity=IRRiskLevel.LOW,
                message="no blocker",
            )],
        )
        assert r.deployable() is True

    def test_manual_review_required_property(self):
        r = ValidationReport(
            issues=[ValidationIssue(
                category=ValidationCategory.MANUAL_REVIEW,
                severity=IRRiskLevel.MEDIUM,
                message="needs review",
            )],
        )
        assert r.manual_review_required is True

    def test_deployable_and_manual_review_independent(self):
        """deployable=True + manual_review_required=True is valid."""
        r = ValidationReport(
            issues=[ValidationIssue(
                category=ValidationCategory.MANUAL_REVIEW,
                severity=IRRiskLevel.MEDIUM,
                message="needs review but not blocking",
            )],
        )
        assert r.deployable() is True
        assert r.manual_review_required is True


class TestValidationPolicyContract:
    def test_default_policy_allows_deploy_with_low_only(self):
        r = ValidationReport(
            issues=[ValidationIssue(
                category=ValidationCategory.SEMANTIC,
                severity=IRRiskLevel.LOW,
                message="minor",
            )],
        )
        policy = ValidationPolicy()
        assert policy.allows_deploy(r) is True

    def test_default_policy_blocks_high(self):
        r = ValidationReport(
            issues=[ValidationIssue(
                category=ValidationCategory.SEMANTIC,
                severity=IRRiskLevel.HIGH,
                message="blocker",
            )],
        )
        policy = ValidationPolicy(max_high=0)
        assert policy.allows_deploy(r) is False

    def test_default_policy_rejects_critical(self):
        r = ValidationReport(
            issues=[ValidationIssue(
                category=ValidationCategory.CONVERSION,
                severity=IRRiskLevel.CRITICAL,
                message="unsupported",
            )],
        )
        policy = ValidationPolicy(max_critical=0)
        assert policy.allows_deploy(r) is False

    def test_policy_categories_to_block(self):
        r = ValidationReport(
            issues=[ValidationIssue(
                category=ValidationCategory.RESIDUE,
                severity=IRRiskLevel.LOW,
                message="residual",
            )],
        )
        policy = ValidationPolicy(
            categories_to_block=[ValidationCategory.RESIDUE],
        )
        assert policy.allows_deploy(r) is False
