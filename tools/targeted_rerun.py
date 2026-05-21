"""Targeted re-run for flaky corpus cases. Runs each N times, captures full results."""

import json, sys, time, urllib.request, urllib.error
from pathlib import Path

API_BASE = "http://127.0.0.1:5008/api/translate"
CORPUS_DIR = Path("bench/cases/corpus")
RUNS_PER_CASE = 3

cases = [
    "firewall/corpus-fw-nat-001",
    "firewall/corpus-fw-ipsec-vpn-001",
    "firewall/corpus-fw-nat-server-001",
]

def call_api(source_config, from_vendor, to_vendor, source_platform, target_platform):
    payload = {
        "config_text": source_config,
        "from_vendor": from_vendor,
        "to_vendor": to_vendor,
        "source_platform": source_platform,
        "target_platform": target_platform,
    }
    req = urllib.request.Request(
        API_BASE,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    t0 = time.time()
    try:
        resp = urllib.request.urlopen(req, timeout=180)
        body = json.loads(resp.read())
        elapsed = int((time.time() - t0) * 1000)
        result = body.get("result", {})
        meta = result.get("meta", {})
        validation = result.get("validation", {})
        translated = result.get("translated", "")
        return {
            "elapsed_ms": elapsed,
            "status": "ok",
            "deployable": validation.get("deployable", meta.get("deployable")),
            "manual_review_required": validation.get("manual_review_required", meta.get("manual_review_required")),
            "level": validation.get("level", meta.get("level", "info")),
            "errors": validation.get("errors", []),
            "warnings": validation.get("warnings", []),
            "translated_excerpt": translated[:500] if translated else "",
            "request_id": body.get("request_id"),
            "model": body.get("model"),
            "risk_signals": meta.get("risk_signals", []),
        }
    except urllib.error.HTTPError as e:
        elapsed = int((time.time() - t0) * 1000)
        body = e.read()
        return {"elapsed_ms": elapsed, "status": "http_error", "code": e.code, "body": body.decode(errors="replace")[:500]}
    except urllib.error.URLError as e:
        elapsed = int((time.time() - t0) * 1000)
        return {"elapsed_ms": elapsed, "status": "url_error", "error": str(e.reason)}
    except Exception as e:
        elapsed = int((time.time() - t0) * 1000)
        return {"elapsed_ms": elapsed, "status": "exception", "error": str(e)[:500]}


all_results = {}

for case_path in cases:
    case_file = CORPUS_DIR / f"{case_path}.json"
    case_name = case_file.stem
    case_data = json.loads(case_file.read_text())
    src_cfg = case_data["source_config"]
    sv = case_data["source_vendor"]
    tv = case_data["target_vendor"]
    sp = case_data.get("source_platform", "")
    tp = case_data.get("target_platform", "")

    print(f"\n{'='*60}")
    print(f"Case: {case_name}")
    print(f"  Source: {sv}/{sp}  Target: {tv}/{tp}")
    print(f"  Risk: {case_data['risk']}  Expected: dep={case_data['expected']['deployable']} mr={case_data['expected']['manual_review_required']}")
    print(f"{'='*60}")

    results = []
    for i in range(RUNS_PER_CASE):
        print(f"\n  Run {i+1}/{RUNS_PER_CASE}...", end=" ", flush=True)
        result = call_api(src_cfg, sv, tv, sp, tp)
        results.append(result)

        if result["status"] == "ok":
            dep = result["deployable"]
            mr = result["manual_review_required"]
            level = result["level"]
            ms = result["elapsed_ms"]
            excerpt = result["translated_excerpt"][:200].replace("\n", "\\n")
            has_review = "MANUAL_REVIEW" in excerpt
            has_review_str = " [MANUAL_REVIEW!]" if has_review else ""
            errors = "; ".join(result["errors"][:3])
            warnings = "; ".join(result["warnings"][:3])
            print(f"OK {ms}ms dep={dep} mr={mr} level={level}{has_review_str}")
            if errors:
                print(f"    errors: {errors}")
            if warnings:
                print(f"    warnings: {warnings}")
        elif result["status"] == "http_error":
            print(f"HTTP {result['code']} ({result['elapsed_ms']}ms)")
        elif result["status"] == "url_error":
            print(f"URL ERROR ({result['elapsed_ms']}ms): {result.get('error','')}")
        else:
            print(f"EXCEPTION ({result['elapsed_ms']}ms): {result.get('error','')}")

    all_results[case_name] = results

print(f"\n\n{'='*60}")
print("SUMMARY")
print(f"{'='*60}")
summary = {}
for case_name, results in all_results.items():
    case_file = CORPUS_DIR / f"firewall/{case_name}.json"
    case_data = json.loads(case_file.read_text())
    exp = case_data["expected"]
    
    passes = sum(1 for r in results if r["status"] == "ok" and r["deployable"] == exp["deployable"])
    total_ok = sum(1 for r in results if r["status"] == "ok")
    
    print(f"\n{case_name}:")
    print(f"  Expected: dep={exp['deployable']} mr={exp['manual_review_required']}")
    print(f"  Pass rate: {passes}/{RUNS_PER_CASE}")
    for i, r in enumerate(results):
        if r["status"] == "ok":
          has_rev = "MANUAL_REVIEW" in r.get("translated_excerpt", "")
          print(f"    Run {i+1}: dep={r['deployable']} mr={r['manual_review_required']} level={r['level']} {r['elapsed_ms']}ms{' MANUAL_REVIEW' if has_rev else ''}")
        else:
          print(f"    Run {i+1}: {r['status']} ({r['elapsed_ms']}ms)")
    
    summary[case_name] = {
        "expected": {"deployable": exp["deployable"], "manual_review_required": exp["manual_review_required"]},
        "runs": [
            {
                "run": i+1,
                "status": r["status"],
                "elapsed_ms": r["elapsed_ms"],
                "deployable": r.get("deployable"),
                "manual_review_required": r.get("manual_review_required"),
                "level": r.get("level"),
                "has_manual_review_marker": "MANUAL_REVIEW" in r.get("translated_excerpt", ""),
                "errors": r.get("errors", []),
                "warnings": r.get("warnings", []),
                "translated_excerpt": r.get("translated_excerpt", "")[:300],
            }
            for i, r in enumerate(results)
        ],
        "pass_count": passes,
        "total": RUNS_PER_CASE,
    }

Path("reports/targeted_rerun.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
print(f"\n\nDetailed results written to reports/targeted_rerun.json")
