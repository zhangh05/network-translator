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
    category = case.get("category", "")
    if category in FAILURE_CATEGORIES and category != "unknown":
        return category
    if status == "unsafe_success":
        return "unsafe_success"
    if "timeout" in err_str or category == "llm_timeout":
        return "llm_timeout"
    if "deployable expected" in err_str or "manual_review_required" in err_str:
        return "validator_false_negative"
    if "missing must_include" in err_str:
        return "llm_quality_issue"
    if "contains forbidden" in err_str:
        return "llm_quality_issue"
    if "connection_error" in category or "500" in err_str:
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
        backlog.append({
            "name": case["name"],
            "path": case.get("path", ""),
            "tier": case.get("tier", ""),
            "domain": case.get("path", "").split("/")[0] if "/" in case.get("path", "") else "",
            "source_vendor": "",
            "target_vendor": "",
            "status": case.get("status", ""),
            "category": cat,
            "priority": pri,
            "errors": case.get("errors", []),
            "meta": case.get("meta", {}),
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
        "| Pri | Case | Domain | Category | Errors |",
        "|-----|------|--------|----------|--------|",
    ])
    for b in backlog:
        err_summary = "; ".join(b["errors"][:2]) if b["errors"] else b["status"]
        lines.append(
            f"| {b['priority']} | {b['name']} | {b['domain']} | {b['category']} | {err_summary[:80]} |"
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
            {"name": b["name"], "priority": b["priority"],
             "category": b["category"], "errors": b["errors"][:2]}
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
