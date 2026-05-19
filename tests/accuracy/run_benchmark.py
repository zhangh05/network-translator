# -*- coding: utf-8 -*-
"""
Accuracy benchmark runner.
Usage:
  PYTHONPATH=. python3 tests/accuracy/run_benchmark.py
  PYTHONPATH=. python3 tests/accuracy/run_benchmark.py --verbose
  PYTHONPATH=. python3 tests/accuracy/run_benchmark.py --update-refs
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.graph.agent import GraphAgent
from core.graph.translation_graph import create_translation_graph, execute_translation_flow
from core import get_llm


REF_FILE = Path(__file__).parent / "reference_results.json"
CASES_FILE = Path(__file__).parent / "translation_cases.json"


def load_cases():
    with open(CASES_FILE) as f:
        return json.load(f)


def evaluate(translated: str, expect_contains: list, expect_forbidden: list) -> dict:
    t = translated.lower()
    passed = 0
    total = len(expect_contains) + len(expect_forbidden)
    details = []
    for kw in expect_contains:
        ok = kw.lower() in t
        details.append({"keyword": kw, "type": "contains", "passed": ok})
        if ok:
            passed += 1
    for kw in expect_forbidden:
        ok = kw.lower() not in t
        details.append({"keyword": kw, "type": "forbidden", "passed": ok})
        if ok:
            passed += 1
    return {"passed": passed, "total": total, "score": passed / max(total, 1), "details": details}


def run_benchmark(cases: list, verbose: bool = False) -> dict:
    llm = None
    skipped_llm = False
    try:
        llm = get_llm()
    except Exception:
        skipped_llm = True

    results = []
    for case in cases:
        cid = case["id"]
        config_text = case["config"]
        from_v = case["from"]
        to_v = case["to"]

        graph = create_translation_graph(enable_diff=True)
        state_result = execute_translation_flow(
            graph, config_text, from_v, to_v, user="benchmark"
        )

        translated = state_result.get("translated", "")
        fallback = state_result.get("fallback_used", False)
        route = state_result.get("route_decision", "unknown")
        cache_hit = state_result.get("cache_hit", False)
        gaps = state_result.get("capability_gaps", [])
        validation_level = state_result.get("validation", {}).get("level", "info")

        eval_result = evaluate(
            translated,
            case.get("expect_contains", []),
            case.get("expect_forbidden", []),
        )

        result = {
            "id": cid,
            "from": from_v,
            "to": to_v,
            "passed": eval_result["passed"],
            "total": eval_result["total"],
            "score": eval_result["score"],
            "fallback": fallback,
            "route": route,
            "cache_hit": cache_hit,
            "validation_level": validation_level,
            "capability_gaps": [
                {"feature": g["feature"], "status": g["status"], "severity": g["severity"]}
                for g in gaps
            ],
        }
        if verbose:
            result["details"] = eval_result["details"]
            result["translated_preview"] = translated[:300]

        results.append(result)

        if verbose:
            status = "PASS" if result["score"] == 1.0 else f"FAIL({result['passed']}/{result['total']})"
            print(f"  [{status}] {cid}  ({from_v}→{to_v})  route={route}  fallback={fallback}")

    total_passed = sum(r["passed"] for r in results)
    total_total = sum(r["total"] for r in results)
    overall = {
        "total_cases": len(cases),
        "passed_checks": total_passed,
        "total_checks": total_total,
        "accuracy": total_passed / max(total_total, 1),
        "full_score_cases": sum(1 for r in results if r["score"] == 1.0),
        "llm_available": not skipped_llm,
        "results": results,
    }
    return overall


def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    update_refs = "--update-refs" in sys.argv

    cases = load_cases()
    print(f"Loading {len(cases)} test cases...")

    overall = run_benchmark(cases, verbose=verbose)

    print(f"\n{'='*50}")
    print(f"  Accuracy: {overall['accuracy']*100:.1f}%")
    print(f"  Cases: {overall['full_score_cases']}/{overall['total_cases']} full score")
    print(f"  Checks: {overall['passed_checks']}/{overall['total_checks']} passed")
    print(f"  LLM: {'available' if overall['llm_available'] else 'UNAVAILABLE'}")
    print(f"{'='*50}")

    if update_refs:
        with open(REF_FILE, "w") as f:
            json.dump(
                {
                    "timestamp": __import__("datetime").datetime.now().isoformat(),
                    "results": overall["results"],
                    "accuracy": overall["accuracy"],
                },
                f, indent=2, ensure_ascii=False,
            )
        print(f"\nReference results saved to {REF_FILE}")

    sys.exit(0 if overall["accuracy"] >= 0.5 else 1)


if __name__ == "__main__":
    main()
