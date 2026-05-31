#!/usr/bin/env python3
"""Emit product capability baseline coverage summary."""

from __future__ import annotations

import json
from pathlib import Path

from core.module_graph.capability_taxonomy import capability_coverage_report


def main() -> int:
    report = capability_coverage_report()
    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    json_path = out_dir / "product_capability_baseline.json"
    md_path = out_dir / "PRODUCT_CAPABILITY_BASELINE.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Product Capability Baseline Coverage",
        "",
        f"- total: {report['summary']['total']}",
        f"- covered: {report['summary']['covered']}",
        f"- missing: {report['summary']['missing']}",
        "",
    ]
    for domain, specs in sorted(report["domains"].items()):
        lines.append(f"## {domain}")
        lines.append("")
        for spec in specs:
            action = spec["default_action"]
            features = ", ".join(spec["module_features"])
            lines.append(f"- `{spec['capability_id']}`: {action}; modules: {features}")
        lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    print(json.dumps(report["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
