#!/usr/bin/env python3
"""Phase 8A: Performance baseline runner.

Usage:
    PYTHONPATH=. python3 scripts/run_baseline.py

Outputs:
    docs/PHASE8_PERF_BASELINE.md   — Human-readable baseline report
    docs/phase8_perf_baseline.json — Machine-readable baseline data
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.batch import BatchTask, run_batch
from core.batch.sample_tasks import ALL_SAMPLE_TASKS


def _format_ms(ms: float) -> str:
    if ms < 1000:
        return f"{ms:.1f}ms"
    return f"{ms/1000:.2f}s"


def _perf_summary(results: list) -> dict:
    timings = [r.timing_ms.get("total", 0) for r in results]
    validate_timings = [r.timing_ms.get("validate", 0) for r in results if "validate" in r.timing_ms]
    return {
        "total_tasks": len(results),
        "total_time_ms": round(sum(timings), 2),
        "mean_per_task_ms": round(sum(timings) / max(len(timings), 1), 2),
        "min_ms": round(min(timings), 2) if timings else 0,
        "max_ms": round(max(timings), 2) if timings else 0,
        "mean_validate_ms": round(sum(validate_timings) / max(len(validate_timings), 1), 2),
        "throughput_tasks_per_sec": round(
            len(timings) / (sum(timings) / 1000) if sum(timings) > 0 else 0, 2,
        ),
    }


def main():
    print("=" * 60)
    print("Phase 8A: Performance Baseline Runner")
    print("=" * 60)

    tasks: list[BatchTask] = ALL_SAMPLE_TASKS
    print(f"\nRunning {len(tasks)} validation tasks...\n")

    t0 = time.perf_counter()
    result = run_batch(tasks, progress_callback=lambda c, t: print(f"  [{c}/{t}]", end="\r"))
    elapsed = time.perf_counter() - t0

    print(f"\n\nCompleted in {elapsed:.2f}s")
    print(f"  Passed: {result.passed}")
    print(f"  Failed (non-deployable): {result.failed}")
    print(f"  Errors: {result.error_count}")

    # Build performance summary
    summary = _perf_summary(result.tasks)
    print(f"\n--- Performance Summary ---")
    print(f"  Total time:  {_format_ms(summary['total_time_ms'])}")
    print(f"  Mean/task:   {_format_ms(summary['mean_per_task_ms'])}")
    print(f"  Min:         {_format_ms(summary['min_ms'])}")
    print(f"  Max:         {_format_ms(summary['max_ms'])}")
    print(f"  Mean validate: {_format_ms(summary['mean_validate_ms'])}")
    print(f"  Throughput:  {summary['throughput_tasks_per_sec']} tasks/sec")

    # Detailed per-task results
    rows = []
    for tr in result.tasks:
        status = "ERR" if tr.error else ("PASS" if tr.report and tr.report.deployable() else "FAIL")
        t = tr.timing_ms.get("total", 0)
        rows.append({
            "name": tr.task.name,
            "status": status,
            "source": tr.task.source_vendor,
            "target": tr.task.target_vendor,
            "domain": tr.task.domain,
            "timing_ms": t,
            "issues": tr.metrics_snapshot.get("total_issues", "?"),
            "verifiability": tr.metrics_snapshot.get("capability_verifiability_rate", "?"),
        })

    # Print table
    print(f"\n{'Name':38s} {'Src':12s} {'Tgt':12s} {'Domain':10s} {'Time':8s} {'Issues':6s} {'Status':6s}")
    print("-" * 100)
    for r in rows:
        t_str = _format_ms(r["timing_ms"])
        print(f"{r['name']:38s} {r['source']:12s} {r['target']:12s} {r['domain']:10s} {t_str:>8s} {str(r['issues']):6s} {r['status']:6s}")

    # Write baseline data
    import subprocess
    commit_hash = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
    ).stdout.strip() or "unknown"

    baseline_data = {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "commit_hash": commit_hash,
        "run_id": f"baseline-{time.strftime('%Y%m%d-%H%M%S')}",
        "python_version": sys.version.split()[0],
        "task_count": len(tasks),
        "performance": summary,
        "results": [r.to_dict() for r in result.tasks],
        "per_task": [
            {
                "name": r.task.name,
                "source": r.task.source_vendor,
                "target": r.task.target_vendor,
                "domain": r.task.domain,
                "timing_ms": r.timing_ms,
                "metrics": r.metrics_snapshot,
                "error": r.error,
            }
            for r in result.tasks
        ],
    }

    os.makedirs("docs", exist_ok=True)

    with open("docs/phase8_perf_baseline.json", "w") as f:
        json.dump(baseline_data, f, indent=2, default=str)
    print(f"\nMachine-readable baseline written to docs/phase8_perf_baseline.json")

    # Write Markdown report
    md = _build_markdown(summary, rows, result, commit_hash)
    with open("docs/PHASE8_PERF_BASELINE.md", "w") as f:
        f.write(md)
    print(f"Human-readable baseline written to docs/PHASE8_PERF_BASELINE.md")

    if result.error_count > 0:
        print(f"\nWARNING: {result.error_count} task(s) had errors.")
        sys.exit(1)

    print("\nDone.")


def _build_markdown(summary: dict, rows: list, result, commit_hash: str) -> str:
    lines = [
        "# Phase 8A: Performance Baseline Report",
        "",
        f"> Generated at {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"> Python {sys.version.split()[0]}",
        f"> Commit: {commit_hash}",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total tasks | {summary['total_tasks']} |",
        f"| Passed | {result.passed} |",
        f"| Failed (non-deployable) | {result.failed} |",
        f"| Errors | {result.error_count} |",
        f"| Total wall time | {_format_ms(summary['total_time_ms'])} |",
        f"| Mean per task | {_format_ms(summary['mean_per_task_ms'])} |",
        f"| Min task time | {_format_ms(summary['min_ms'])} |",
        f"| Max task time | {_format_ms(summary['max_ms'])} |",
        f"| Mean validate phase | {_format_ms(summary['mean_validate_ms'])} |",
        f"| Throughput | {summary['throughput_tasks_per_sec']} tasks/sec |",
        "",
        "## Task Details",
        "",
        "| # | Name | Source | Target | Domain | Time | Issues | Status |",
        "|---|------|--------|--------|--------|------|--------|--------|",
    ]
    for i, r in enumerate(rows, 1):
        t_str = _format_ms(r["timing_ms"])
        lines.append(
            f"| {i} | {r['name']} | {r['source']} | {r['target']} "
            f"| {r['domain']} | {t_str} | {r['issues']} | {r['status']} |"
        )

    lines.extend([
        "",
        "## Domain Distribution",
        "",
    ])
    domains = {}
    for r in rows:
        domains.setdefault(r["domain"], {"count": 0, "total_ms": 0})
        domains[r["domain"]]["count"] += 1
        domains[r["domain"]]["total_ms"] += r["timing_ms"]
    for d, info in sorted(domains.items()):
        avg = info["total_ms"] / info["count"]
        lines.append(f"- **{d}**: {info['count']} tasks, avg {_format_ms(avg)}")

    lines.extend([
        "",
        "## Notes",
        "",
        "- All timings are wall-clock for the validate-only pipeline (no LLM calls).",
        "- Tasks use synthetic IR data constructed from dataclass to_dict().",
        "- The batch runner is in `core/batch/` — see `scripts/run_baseline.py`.",
        "- Full-pipeline throughput (parse + translate + validate) will be lower",
        "  due to LLM API latency.",
        "",
    ])
    return "\n".join(lines)


if __name__ == "__main__":
    main()
