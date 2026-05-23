from __future__ import annotations

from core.ir_models.enums import IRRiskLevel
from core.validator.base import ValidationReport


_SEVERITY_LABELS = {
    IRRiskLevel.CRITICAL: "🔴 CRITICAL",
    IRRiskLevel.HIGH: "🟠 HIGH",
    IRRiskLevel.MEDIUM: "🟡 MEDIUM",
    IRRiskLevel.LOW: "🔵 LOW",
}


def report_to_markdown(report: ValidationReport) -> str:
    lines: list[str] = []
    lines.append("# Validation Report")
    lines.append("")

    summary = report.summary()
    lines.append("## Summary")
    lines.append(f"- Total issues: {len(report.issues)}")
    lines.append(f"- Deployable: {'✅ Yes' if report.deployable() else '❌ No'}")
    lines.append(f"- Manual review required: {'✅ Yes' if report.manual_review_required else '❌ No'}")
    for severity in (IRRiskLevel.CRITICAL, IRRiskLevel.HIGH, IRRiskLevel.MEDIUM, IRRiskLevel.LOW):
        count = summary.get(severity, 0)
        if count:
            label = _SEVERITY_LABELS.get(severity, severity.value)
            lines.append(f"- {label}: {count}")
    lines.append("")

    # Capability boundary section
    cap_metrics = report.metadata.get("capability_metrics")
    if cap_metrics:
        lines.append("## Capability Boundary")
        lines.append(
            f"- **Verifiability rate**: {cap_metrics.get('verifiability_rate', 'N/A')}"
        )
        lines.append(
            f"- **Auto-verifiable features**: {cap_metrics.get('auto_verifiable', 'N/A')}"
        )
        lines.append(
            f"- **Manual review features**: {cap_metrics.get('manual_review', 'N/A')}"
        )
        lines.append(
            f"- **Unsupported features**: {cap_metrics.get('unsupported', 'N/A')}"
        )
        lines.append(
            f"- **Total features considered**: {cap_metrics.get('total_features_considered', 'N/A')}"
        )
        cap_gaps = report.metadata.get("capability_gaps")
        if cap_gaps:
            lines.append(f"- **Capability gaps**: {', '.join(sorted(cap_gaps))}")
        cap_manual = report.metadata.get("capability_manual_review_items")
        if cap_manual:
            lines.append("- **Manual review items (by reason)**:")
            for reason, keys in sorted(cap_manual.items()):
                lines.append(f"  - {reason}: {', '.join(sorted(keys))}")
        lines.append("")

    if report.metadata:
        lines.append("## Metadata")
        for key, value in report.metadata.items():
            if key in ("capability_metrics", "capability_gaps", "capability_manual_review_items"):
                continue
            lines.append(f"- **{key}**: {value}")
        lines.append("")

    if report.issues:
        lines.append("## Issues")
        for i, issue in enumerate(report.issues, start=1):
            severity_label = _SEVERITY_LABELS.get(issue.severity, issue.severity.value)
            line_info = f" (line {issue.line})" if issue.line else ""
            lines.append(f"### {i}. {severity_label}: {issue.message}{line_info}")
            if issue.field:
                lines.append(f"- **Field**: {issue.field}")
            if issue.category:
                lines.append(f"- **Category**: {issue.category.value}")
            if issue.rule_id:
                lines.append(f"- **Rule ID**: {issue.rule_id}")
            if issue.source_ref:
                lines.append(f"- **Source ref**: {issue.source_ref}")
            if issue.rendered_ref:
                lines.append(f"- **Rendered ref**: {issue.rendered_ref}")
            if issue.suggestion:
                lines.append(f"- **Suggestion**: {issue.suggestion}")
            if issue.target_span:
                src = "".join(issue.target_span.source_text) if issue.target_span.source_text else ""
                if src:
                    lines.append(f"- **Target**: `{src.strip()}`")
            if issue.source_span:
                src = "".join(issue.source_span.source_text) if issue.source_span.source_text else ""
                if src:
                    lines.append(f"- **Source**: `{src.strip()}`")
            lines.append("")

    # Manual review checklist
    manual_issues = [i for i in report.issues
                     if i.category.value == "manual_review"]
    if manual_issues:
        lines.append("## Manual Review Checklist")
        lines.append("")
        lines.append("| # | Severity | Message | Field | Suggestion |")
        lines.append("|---|----------|---------|-------|------------|")
        for i, issue in enumerate(manual_issues, start=1):
            sev = _SEVERITY_LABELS.get(issue.severity, issue.severity.value)
            msg = issue.message.replace("\n", " ")
            fld = issue.field or ""
            sug = (issue.suggestion or "").replace("\n", " ")
            lines.append(f"| {i} | {sev} | {msg} | {fld} | {sug} |")
        lines.append("")

    return "\n".join(lines)
