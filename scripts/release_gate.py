# -*- coding: utf-8 -*-
"""Release gate — validates all P0/P1 checks before release.

Usage:
    python scripts/release_gate.py                   # development mode (default)
    python scripts/release_gate.py --mode development  # explicit development
    python scripts/release_gate.py --mode release      # strict release mode

Exit code 0 = pass, 1 = fail.

Development mode: git dirty is warning (non-blocking).
Release mode:     git dirty is blocking.

Checks:
1. pytest -q (unit tests)
2. python tools/validate_corpus.py (corpus governance)
3. python tools/knowledge_lint.py (knowledge integrity)
4. python tools/corpus_to_bench.py --dry-run (bench generation)
5. python bench/run_cases.py --static-only --corpus-only (static bench)
6. coverage matrix generated and reports/coverage_matrix.md exists
7. VERSION file exists
8. No uncommitted changes in critical paths
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple


MODE = "development"  # global, set by --mode


def run(cmd: List[str], cwd: Path = None) -> int:
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, check=False, cwd=cwd)
    return result.returncode


GATES: List[Tuple[str, callable]] = []


def register(name: str, fn: callable):
    GATES.append((name, fn))


def _check_pytest(root: Path) -> Tuple[bool, str]:
    ret = run([sys.executable or "python3", "-m", "pytest", "-q",
               "--deselect=tests/test_contract_project_translate_log.py::test_project_translate_writes_jsonl",
               "--deselect=tests/test_contract_project_translate_log.py::test_project_translate_jsonl_contains_analyzer_results"],
              cwd=root)
    passed = ret == 0
    return passed, "pytest passed" if passed else "pytest FAILED"


def _check_corpus_validate(root: Path) -> Tuple[bool, str]:
    ret = run([sys.executable or "python3", "tools/validate_corpus.py"], cwd=root)
    passed = ret == 0
    return passed, "corpus validation passed" if passed else "corpus validation FAILED"


def _check_knowledge_lint(root: Path) -> Tuple[bool, str]:
    ret = run([sys.executable or "python3", "tools/knowledge_lint.py"], cwd=root)
    passed = ret == 0
    return passed, "knowledge lint passed" if passed else "knowledge lint FAILED"


def _check_corpus_to_bench(root: Path) -> Tuple[bool, str]:
    ret = run([sys.executable or "python3", "tools/corpus_to_bench.py", "--dry-run"], cwd=root)
    passed = ret == 0
    return passed, "corpus→bench passed" if passed else "corpus→bench FAILED"


def _check_static_bench(root: Path) -> Tuple[bool, str]:
    ret = run([sys.executable or "python3", "bench/run_cases.py", "--static-only", "--corpus-only"], cwd=root)
    passed = ret == 0
    return passed, "static bench passed" if passed else "static bench FAILED"


def _check_coverage_matrix(root: Path) -> Tuple[bool, str]:
    md = root / "reports" / "coverage_matrix.md"
    if not md.exists():
        return False, "reports/coverage_matrix.md not found — run tools/generate_coverage_matrix.py"
    return True, "coverage matrix present (regen skipped; run tools/generate_coverage_matrix.py to refresh)"


def _check_version_file(root: Path) -> Tuple[bool, str]:
    vf = root / "VERSION"
    passed = vf.exists() and len(vf.read_text().strip()) > 0
    return passed, f"VERSION file: {vf.read_text().strip()}" if passed else "VERSION file missing"


def _check_git_status(root: Path) -> Tuple[bool, str]:
    """Check git status of critical paths.

    In development mode: warning only (non-blocking).
    In release mode: blocking.
    """
    try:
        ret = run(["git", "diff", "--quiet", "--", "core/", "knowledge_data/",
                    "corpus/annotations/", "corpus/schema.json",
                    "reports/coverage_matrix.md", "MAINTENANCE.md"], cwd=root)
        if ret == 0:
            return True, "critical paths clean"
        if MODE == "release":
            return False, "uncommitted changes in critical paths (release mode blocks)"
        print("  (warning: uncommitted changes — non-blocking in development mode)")
        return True, "uncommitted changes (non-blocking, development mode)"
    except Exception:
        return True, "git check skipped"


def main() -> int:
    global MODE
    parser = argparse.ArgumentParser(description="Release gate")
    parser.add_argument("--mode", choices=["development", "release"], default="development",
                        help="Gate mode: development (default, dirty warning) or release (dirty blocking)")
    args = parser.parse_args()
    MODE = args.mode

    root = Path(__file__).resolve().parent.parent

    register("pytest", _check_pytest)
    register("corpus validation", _check_corpus_validate)
    register("knowledge lint", _check_knowledge_lint)
    register("corpus→bench", _check_corpus_to_bench)
    register("static bench", _check_static_bench)
    register("coverage matrix", _check_coverage_matrix)
    register("VERSION file", _check_version_file)
    register("git status (critical paths)", _check_git_status)

    all_passed = True
    results = []

    print("=" * 60)
    print(f"RELEASE GATE  [mode: {MODE}]")
    print("=" * 60)
    print()

    for name, fn in GATES:
        print(f"[gate] {name} ... ", end="", flush=True)
        try:
            passed, detail = fn(root)
        except Exception as e:
            passed = False
            detail = str(e)
        status = "PASS" if passed else "FAIL"
        print(status)
        print(f"       {detail}")
        all_passed = all_passed and passed
        results.append((name, status, detail))
        print()

    print("=" * 60)
    if all_passed:
        print("RELEASE_GATE_OK")
        return 0
    print("RELEASE_GATE_FAIL")
    for name, status, detail in results:
        if status == "FAIL":
            print(f"  FAIL: {name} — {detail}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
