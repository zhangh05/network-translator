"""Phase 8B: CI Quality Gates — layered test execution with regression detection.

Usage:
    PYTHONPATH=. python3 scripts/ci_quality_gates.py [--full] [--json REPORT.json]

Layers:
    Layer 1 (core): Validator + integration + schema + domain + IR + vendor + parser + renderer
                    → zero-tolerance. Any failure blocks.
    Layer 2 (extended): All other tests. Failures NOT in PREEXISTING list → blocks.
    Layer 3 (full):     All tests with --full flag. Same block rules as Layer 2.

Exit codes:
    0  → all gates pass
    1  → Layer 1 regression (core test failure)
    2  → Layer 2 regression (new failure outside pre-existing list)
    3  → both
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import TextIO

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ── Pre-existing failures (known, non-blocking) ──────────────────────────
# These fail due to missing flask/requests in dev env or deprecated analyzers.
# They are NOT counted as regression. Updated: 2026-05-23.
PREEXISTING_FAILURES: list[str] = [
    # test_analyzer_object — deprecated FIREWALL object analyzers
    "tests/test_analyzer_object.py::test_registry_has_address_object_analyzer",
    "tests/test_analyzer_object.py::test_registry_has_service_object_analyzer",
    "tests/test_analyzer_object.py::test_registry_address_object_is_object_analyzer",
    "tests/test_analyzer_object.py::test_registry_service_object_is_object_analyzer",
    "tests/test_analyzer_object.py::test_registry_not_noop_for_address_object",
    "tests/test_analyzer_object.py::test_registry_not_noop_for_service_object",
    "tests/test_analyzer_object.py::test_registry_analyze_all_produces_analyzed_results",
    # test_contract_project_translate_log — requires flask/requests runtime
    "tests/test_contract_project_translate_log.py::test_project_translate_writes_jsonl",
    "tests/test_contract_project_translate_log.py::test_project_translate_jsonl_contains_analyzer_results",
    # test_readyz_production — requires flask production runtime
    "tests/test_readyz_production.py::test_readyz_reports_runtime_checks_and_insecure_settings_file",
    "tests/test_readyz_production.py::test_readyz_reports_feature_registry_loaded",
    # test_v9_stability — requires requests for retry mocks
    "tests/test_v9_stability.py::test_llm_retry_on_transient_http_error",
    "tests/test_v9_stability.py::test_llm_max_retries_not_exceeded_on_success",
]

# ── Core test files (Layer 1) — zero-tolerance ──────────────────────────
CORE_TEST_FILES: list[str] = [
    "tests/test_domain_base.py",
    "tests/test_domain_detector.py",
    "tests/test_ir_base.py",
    "tests/test_ir_enums.py",
    "tests/test_ir_models.py",
    "tests/test_ir_prompt_version.py",
    "tests/test_vendor_base.py",
    "tests/test_vendor_enums.py",
    "tests/test_vendor_profiles.py",
    "tests/test_parser_base.py",
    "tests/test_parser_h3c_comware_switch.py",
    "tests/test_parser_registry.py",
    "tests/test_parser_shared.py",
    "tests/test_renderer_base.py",
    "tests/test_renderer_cisco_ios_xe_switch.py",
    "tests/test_renderer_registry.py",
    "tests/test_validator_base.py",
    "tests/test_validator_capability_baseline.py",
    "tests/test_validator_capability_gap.py",
    "tests/test_validator_composite.py",
    "tests/test_validator_conversion.py",
    "tests/test_validator_coverage.py",
    "tests/test_validator_residue.py",
    "tests/test_validator_semantic.py",
    "tests/test_validator_syntax.py",
    "tests/test_schema_contract.py",
    "tests/test_integration_phase6.py",
    "tests/test_integration_phase7.py",
]


def _find_python() -> str:
    candidates = [
        "venv/bin/python3",
        ".venv/bin/python3",
        "python3",
        "python",
    ]
    for c in candidates:
        p = PROJECT_ROOT / c
        if p.exists():
            return str(p)
    return "python3"


def _parse_pytest_output(text: str) -> list[str]:
    """Extract the list of FAILED test IDs from pytest output.

    Handles two output formats:
      1. Inline:  tests/xxx.py::test_yyy FAILED [  xx%]
      2. Summary: FAILED tests/xxx.py::test_yyy
    """
    failed: list[str] = []
    for line in text.splitlines():
        # Format 1: inline test line with status
        m = re.match(r"^(tests/\S+?) (FAILED|ERROR)\b", line)
        if m:
            test_id = m.group(1).rstrip(".")
            if test_id not in failed:
                failed.append(test_id)
            continue
        # Format 2: summary line
        line_s = line.strip()
        if line_s.startswith("FAILED "):
            parts = line_s.split(" - ", 1)
            test_id = parts[0].replace("FAILED ", "", 1).strip()
            if test_id not in failed:
                failed.append(test_id)
    return failed


def _run_tests(
    test_files: list[str],
    label: str,
    allow_preexisting: bool = False,
    output_file: TextIO = sys.stdout,
    json_report: dict | None = None,
) -> int:
    python = _find_python()
    cmd = [
        python, "-m", "pytest",
        *test_files,
        "-v", "--tb=short",
    ]
    output_file.write(f"\n{'='*60}\n")
    output_file.write(f"  Layer: {label}\n")
    output_file.write(f"  Command: PYTHONPATH=. {' '.join(cmd)}\n")
    output_file.write(f"{'='*60}\n\n")
    output_file.flush()

    env = {**dict(PYTHONPATH=".")}
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env,
                          cwd=str(PROJECT_ROOT))
    output = proc.stdout + "\n" + proc.stderr
    output_file.write(output)
    output_file.flush()

    # Parse summary line (e.g. "524 passed, 20 skipped in 0.43s")
    summary_match = re.search(
        r"=+ (\d+ .+? in [\d.]+s) =+",
        output,
    )
    summary = summary_match.group(0) if summary_match else "(no summary)"

    actual_failures = _parse_pytest_output(output)
    regression = [
        f for f in actual_failures
        if f not in PREEXISTING_FAILURES
    ]

    result = {
        "layer": label,
        "exit_code": proc.returncode,
        "summary": summary,
        "total_failures": len(actual_failures),
        "preexisting_failures": [
            f for f in actual_failures if f in PREEXISTING_FAILURES
        ],
        "regression_failures": regression,
    }

    if allow_preexisting:
        if regression:
            result["gate_result"] = "BLOCKED"
            output_file.write(f"\n  *** GATE BLOCKED: {len(regression)} regression(s) ***\n")
            for f in regression:
                output_file.write(f"    NEW FAILURE: {f}\n")
            output_file.write(f"\n  Pre-existing ({len(result['preexisting_failures'])} known, tolerated):\n")
            for f in result["preexisting_failures"]:
                output_file.write(f"    (known) {f}\n")
        else:
            result["gate_result"] = "PASS"
            output_file.write(f"\n  *** GATE PASS: no regressions ***\n")
            if result["preexisting_failures"]:
                output_file.write(f"  Pre-existing ({len(result['preexisting_failures'])} known, tolerated):\n")
                for f in result["preexisting_failures"]:
                    output_file.write(f"    (known) {f}\n")
    else:
        if actual_failures:
            result["gate_result"] = "BLOCKED"
            output_file.write(f"\n  *** GATE BLOCKED: {len(actual_failures)} failure(s) ***\n")
            for f in actual_failures:
                output_file.write(f"    FAILURE: {f}\n")
        else:
            result["gate_result"] = "PASS"
            output_file.write(f"\n  *** GATE PASS: all {len(test_files)} file(s) clean ***\n")

    if json_report is not None:
        json_report.setdefault("layers", []).append(result)

    return 0 if result["gate_result"] == "PASS" else (1 if not allow_preexisting else 2)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="CI Quality Gates")
    parser.add_argument("--full", action="store_true",
                        help="Also run extended tests (all non-core files)")
    parser.add_argument("--json", type=str, default=None,
                        help="Path to write JSON report")
    args = parser.parse_args()

    json_report: dict | None = {} if args.json else None
    exit_code = 0

    # Layer 1: Core tests (zero-tolerance)
    print(f"Running Layer 1 (core) — {len(CORE_TEST_FILES)} files, zero-tolerance...")
    l1 = _run_tests(CORE_TEST_FILES, "1-core", allow_preexisting=False, json_report=json_report)
    if l1 != 0:
        exit_code = max(exit_code, 1)

    if args.full:
        # Layer 2: Extended tests
        import glob as glob_mod
        all_test_files = sorted(glob_mod.glob("tests/test_*.py"))
        extended = [f for f in all_test_files if f not in CORE_TEST_FILES]

        print(f"\nRunning Layer 2 (extended) — {len(extended)} files, regression-tolerant...")
        l2 = _run_tests(extended, "2-extended", allow_preexisting=True, json_report=json_report)
        if l2 != 0:
            exit_code = max(exit_code, 2)
    else:
        pass  # --full not set; only Layer 1 runs

    if json_report is not None:
        json_report["exit_code"] = exit_code
        if exit_code == 0:
            json_report["verdict"] = "ALL GATES PASS"
        elif exit_code == 1:
            json_report["verdict"] = "BLOCKED: Layer 1 regression"
        elif exit_code == 2:
            json_report["verdict"] = "BLOCKED: Layer 2 regression"
        else:
            json_report["verdict"] = "BLOCKED: Layer 1 + Layer 2 regression"

        report_path = Path(args.json)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(json_report, indent=2))
        print(f"\nJSON report written to {report_path}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
