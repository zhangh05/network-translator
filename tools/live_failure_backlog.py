#!/usr/bin/env python3
"""Generate failure backlog from live report JSON.

Usage:
    python tools/live_failure_backlog.py bench/live_report.json
    python tools/live_failure_backlog.py bench/live_report.json --output reports/live_failure_backlog.md
"""
import json, os, sys, argparse
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

FAILURE_CATEGORIES = {
    "annotation_issue", "knowledge_gap", "prompt_issue",
    "validator_false_positive", "validator_false_negative",
    "analyzer_gap", "platform_mapping_issue", "llm_quality_issue",
    "llm_timeout", "unsafe_success", "frontend_api_issue",
    "infra_issue", "unknown",
}

def categorize_case(case: dict) -> str:
    status = case.get("status", "")
    errors = case.get("errors", [])
    err_str = " ".join(errors).lower()
    reason = (case.get("failure_reason", "") or "").lower()
    full_str = f"{err_str} {reason}"
    category = case.get("category", "")
    if category in FAILURE_CATEGORIES and category != "unknown":
        return category
    if status == "unsafe_success":
        return "unsafe_success"
    if "timeout" in full_str or category == "llm_timeout":
        return "llm_timeout"
    # Specific patterns checked before generic deployable-expected
    if "missing must_include" in full_str:
        return "llm_quality_issue"
    if "contains forbidden" in full_str:
        return "llm_quality_issue"
    if "deployable expected" in full_str or "manual_review_required" in full_str:
        deployable = case.get("deployable")
        if deployable is True:
            # System produced clean output but annotation expected failure
            return "annotation_issue"
        # System returned deployable=False — check if blocking was correct
        # If only deployable mismatch (no infra/timeout), the validator
        # correctly blocked bad LLM output
        if "500" not in full_str and "timeout" not in full_str:
            return "llm_quality_issue"
        return "validator_false_negative"
    if "connection_error" in category or "500" in full_str:
        return "infra_issue"
    if "500" in full_str or "http" in full_str:
        return "infra_issue"
    return "unknown"

def priority_for(category: str) -> str:
    p0 = {"unsafe_success", "validator_false_negative", "infra_issue"}
    p1 = {"llm_quality_issue", "llm_timeout", "knowledge_gap", "prompt_issue",
          "analyzer_gap", "platform_mapping_issue"}
    if category in p0:
        return "P0"
    if category in p1:
        return "P1"
    return "P2"

def parse_args():
    parser = argparse.ArgumentParser(description="Generate failure backlog from live report")
    parser.add_argument("input", help="Path to live_report.json")
    parser.add_argument("--output", default=str(PROJECT_ROOT / "reports" / "live_failure_backlog.md"),
                        help="Output markdown path")
    parser.add_argument("--summary-only", action="store_true", help="Only print summary JSON to stdout")
    return parser.parse_args()

def main():
    args = parse_args()
    with open(args.input) as f:
        data = json.load(f)

    backlog = []
    for case in data.get("cases", []):
        if case.get("status") in ("pass", "skip"):
            continue
        cat = categorize_case(case)
        pri = priority_for(cat)
        features = case.get("features", [])
        if isinstance(features, list):
            features_str = ", ".join(features[:5])
        else:
            features_str = str(features)[:80]
        backlog.append({
            "name": case["name"],
            "path": case.get("path", ""),
            "case_id": case.get("case_id", ""),
            "request_id": case.get("request_id", ""),
            "tier": case.get("tier", ""),
            "domain": case.get("source_domain", "") or (case.get("path", "").split("/")[0] if "/" in case.get("path", "") else ""),
            "source_vendor": case.get("source_vendor", ""),
            "target_vendor": case.get("target_vendor", ""),
            "target_domain": case.get("target_domain", ""),
            "features": features_str,
            "status": case.get("status", ""),
            "category": cat,
            "priority": pri,
            "deployable": case.get("deployable", None),
            "manual_review_required": case.get("manual_review_required", None),
            "validation_level": case.get("validation_level", ""),
            "errors": case.get("errors", []),
            "failure_reason": case.get("failure_reason", ""),
            "meta": case.get("meta", {}),
            "capability_gaps": case.get("capability_gaps", []),
            "analyzer_results": case.get("analyzer_results", []),
        })

    # Sort by priority
    pri_order = {"P0": 0, "P1": 1, "P2": 2}
    backlog.sort(key=lambda x: (pri_order.get(x["priority"], 99), x["name"]))

    if args.summary_only:
        summary = {
            "total": len(backlog),
            "by_priority": dict(Counter(b["priority"] for b in backlog)),
            "by_category": dict(Counter(b["category"] for b in backlog)),
        }
        print(json.dumps(summary, indent=2))
        return

    # Write MD
    lines = [
        "# Live Failure Backlog",
        "",
        f"Generated: {__import__('time').strftime('%Y-%m-%d %H:%M:%S')}",
        f"Source: {args.input}",
        f"Total failures: {len(backlog)}",
        "",
        "## Priority Distribution",
        "",
    ]
    pcount = Counter(b["priority"] for b in backlog)
    for p in ("P0", "P1", "P2"):
        lines.append(f"- **{p}**: {pcount.get(p, 0)}")
    lines.append("")

    lines.extend([
        "## Category Distribution",
        "",
    ])
    ccount = Counter(b["category"] for b in backlog)
    for cat, cnt in sorted(ccount.items(), key=lambda x: -x[1]):
        lines.append(f"- **{cat}**: {cnt}")
    lines.append("")

    lines.extend([
        "## Backlog",
        "",
        "| Pri | Case | Domain | Src→Tgt | Features | Category | Reason | Deployable | MRev |",
        "|-----|------|--------|---------|----------|----------|--------|------------|------|",
    ])
    for b in backlog:
        src_tgt = f"{b['source_vendor']}→{b['target_vendor']}" if b['source_vendor'] and b['target_vendor'] else ""
        feats = b.get("features", "")[:40]
        reason = b.get("failure_reason", "")[:60] or ("; ".join(b["errors"][:2])[:60] if b["errors"] else b["status"])
        dep = "✓" if b.get("deployable") else "✗" if b.get("deployable") is False else "?"
        mrev = "⚠" if b.get("manual_review_required") else "✓" if b.get("manual_review_required") is False else "?"
        lines.append(
            f"| {b['priority']} | {b['name']} | {b['domain']} | {src_tgt} | {feats} | {b['category']} | {reason} | {dep} | {mrev} |"
        )

    # Write summary JSON
    summary_path = PROJECT_ROOT / "reports" / "live_summary.json"
    summary = {
        "generated_at": __import__('time').strftime('%Y-%m-%dT%H:%M:%S'),
        "source": args.input,
        "total": len(backlog),
        "by_priority": dict(pcount),
        "by_category": dict(ccount),
        "failures": [
            {"name": b["name"], "case_id": b["case_id"], "request_id": b["request_id"],
             "priority": b["priority"], "category": b["category"],
             "source_vendor": b["source_vendor"], "target_vendor": b["target_vendor"],
             "features": b["features"], "deployable": b["deployable"],
             "manual_review_required": b["manual_review_required"],
             "failure_reason": b["failure_reason"],
             "errors": b["errors"][:2]}
            for b in backlog
        ],
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))

    lines.append("")
    lines.append(f"Summary JSON: {summary_path}")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n")
    print(f"Backlog: {output_path}")
    print(f"Summary: {summary_path}")

if __name__ == "__main__":
    main()
