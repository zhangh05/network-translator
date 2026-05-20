# -*- coding: utf-8 -*-
"""Benchmark case runner — static validation + live E2E checks with tier support."""
import json, os, sys, glob, time, argparse
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

CASES_DIR = PROJECT_ROOT / "bench" / "cases"
SCHEMA_PATH = CASES_DIR / "schema.json"

RESULTS: dict = {}

REQUEST_TIMEOUT = int(os.environ.get("BENCH_TIMEOUT", "180"))


def load_schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def get_tier(case):
    """Assign tier from case's explicit field or derive from risk level."""
    explicit = case.get("tier")
    if explicit in ("smoke", "core", "full"):
        return explicit
    risk = case.get("risk", "low")
    mapping = {"low": "smoke", "medium": "core", "high": "full"}
    return mapping.get(risk, "full")


def discover_cases(tier=None, domain=None, vendor=None, feature=None):
    cases = []
    for p in sorted(CASES_DIR.rglob("*.json")):
        if p.name == "schema.json":
            continue
        with open(p) as f:
            try:
                case = json.load(f)
            except json.JSONDecodeError:
                print(f"  INVALID JSON: {p}")
                continue
        case["_path"] = str(p.relative_to(CASES_DIR))
        case["_tier"] = get_tier(case)
        if tier and case["_tier"] != tier:
            continue
        if domain and case.get("source_domain") != domain:
            continue
        if vendor and case.get("source_vendor") != vendor:
            continue
        if feature:
            cf = ",".join(case.get("features", []))
            if feature not in cf:
                continue
        cases.append(case)
    return cases


def validate_schema(case, schema):
    required = schema.get("required", [])
    for key in required:
        if key not in case:
            return f"missing required key: {key}"
    exp = case.get("expected", {})
    for r in ["deployable", "manual_review_required", "no_markdown_fence", "no_placeholder"]:
        if r not in exp:
            return f"expected missing: {r}"
    if not isinstance(case.get("features"), list) or len(case["features"]) == 0:
        return "features must be non-empty list"
    if not isinstance(case.get("source_config"), str) or len(case["source_config"].strip()) < 10:
        return "source_config too short"
    return None


def run_static(case):
    errors = []
    exp = case["expected"]

    if not isinstance(exp["deployable"], bool):
        errors.append("expected.deployable must be bool")
    if not isinstance(exp["manual_review_required"], bool):
        errors.append("expected.manual_review_required must be bool")
    if not isinstance(exp["no_markdown_fence"], bool):
        errors.append("expected.no_markdown_fence must be bool")
    if not isinstance(exp["no_placeholder"], bool):
        errors.append("expected.no_placeholder must be bool")

    if "must_include" in exp and not isinstance(exp["must_include"], list):
        errors.append("expected.must_include must be list")
    if "must_not_include" in exp and not isinstance(exp["must_not_include"], list):
        errors.append("expected.must_not_include must be list")

    cfg = case["source_config"]
    if any(marker in cfg for marker in ["TODO", "<", "PLACEHOLDER"]):
        errors.append("source_config contains placeholder markers")

    if case["risk"] == "high":
        if exp.get("deployable") is not False and exp.get("manual_review_required") is not True:
            errors.append("high-risk case must have deployable=false or manual_review_required=true")

    return errors


def check_translated(case, translated, meta):
    errors = []
    exp = case["expected"]

    if exp.get("no_markdown_fence"):
        if "```" in translated or "~~~" in translated:
            errors.append("contains markdown fence")

    if exp.get("no_placeholder"):
        for marker in ["<", "TODO", "PLACEHOLDER", "FIXME"]:
            if marker in translated and marker != "<":
                errors.append(f"contains placeholder: {marker}")
        if "<" in translated and ">" in translated:
            errors.append("contains angle-bracket placeholder")

    if exp.get("must_include"):
        for kw in exp["must_include"]:
            if kw.lower() not in translated.lower():
                errors.append(f"missing must_include: {kw}")

    if exp.get("must_not_include"):
        for kw in exp["must_not_include"]:
            if kw.lower() in translated.lower():
                errors.append(f"contains forbidden: {kw}")

    if meta:
        ed = exp.get("deployable")
        if ed is not None and meta.get("deployable") != ed:
            errors.append(f"deployable expected={ed} got={meta.get('deployable')}")

        if exp.get("manual_review_required") is not None:
            expected_mrr = exp["manual_review_required"]
            actual_mrr = meta.get("manual_review_required", False)
            if expected_mrr and not actual_mrr:
                errors.append("expected manual_review_required=True but system returned False")

        if exp.get("max_level"):
            level = meta.get("level", "info")
            level_rank = {"info": 0, "warning": 1, "error": 2}
            if level_rank.get(level, 0) > level_rank.get(exp["max_level"], 0):
                errors.append(f"level {level} exceeds max {exp['max_level']}")

        # ── Enhanced live checks ──
        if meta.get("capability_gaps"):
            if isinstance(meta["capability_gaps"], list) and len(meta["capability_gaps"]) > 0:
                errors.append(f"capability_gaps present: {meta['capability_gaps']}")

        if meta.get("analyzer_results"):
            if isinstance(meta.get("analyzer_results"), list) and len(meta["analyzer_results"]) > 0:
                pass  # acceptable — analyzer results are informational

    return errors


def _summarize_analyzers(analyzer_results):
    """Build a concise analyzer findings summary for live failure output."""
    if not analyzer_results or not isinstance(analyzer_results, list):
        return {}
    summary = {}
    for ar in analyzer_results:
        if isinstance(ar, dict):
            feat = ar.get("feature", "?")
            risk = ar.get("risk_level", "none")
            if risk not in ("none", "info"):
                summary[feat] = {"risk": risk, "rules_count": len(ar.get("rules", []))}
    return summary


def run_live(case):
    import requests
    BASE = os.environ.get("BENCH_API_BASE", "http://127.0.0.1:5008")
    session = requests.Session()
    session.trust_env = False
    session.proxies = {"http": "", "https": ""}

    payload = {
        "config_text": case["source_config"],
        "from_vendor": case["source_vendor"],
        "to_vendor": case["target_vendor"],
        "source_domain": case["source_domain"],
        "target_domain": case["target_domain"],
        "source_platform": case.get("source_platform", ""),
        "target_platform": case.get("target_platform", ""),
    }

    t0 = time.time()
    try:
        resp = session.post(f"{BASE}/api/translate", json=payload, timeout=REQUEST_TIMEOUT)
        elapsed = time.time() - t0
    except requests.exceptions.ReadTimeout:
        elapsed = time.time() - t0
        return {
            "status": "error",
            "category": "llm_timeout",
            "error": f"LLM translation timed out ({REQUEST_TIMEOUT}s)",
            "elapsed": elapsed or REQUEST_TIMEOUT,
            "deployable": False,
            "manual_review_required": True,
            "detail": {
                "meta": {"level": "error", "deployable": False, "manual_review_required": True, "capability_gaps": []},
                "validation": {"valid": False, "level": "error", "deployable": False, "manual_review_required": True, "errors": [f"LLM timeout ({REQUEST_TIMEOUT}s)"], "warnings": []},
            },
        }
    except Exception as e:
        return {"status": "error", "category": "connection_error", "error": str(e), "elapsed": 0}

    if resp.status_code != 200:
        return {"status": "fail", "error": f"HTTP {resp.status_code}", "elapsed": elapsed}

    try:
        result = resp.json()
    except Exception:
        return {"status": "fail", "error": "invalid JSON response", "elapsed": elapsed}

    translated = result.get("result", {}).get("translated", "")
    meta = result.get("result", {})
    validation = result.get("result", {}).get("validation", {}) or {}
    meta["level"] = validation.get("level", "")
    meta["deployable"] = validation.get("deployable")
    meta["manual_review_required"] = validation.get("manual_review_required")
    meta["capability_gaps"] = meta.get("capability_gaps", [])
    meta["analyzer_results"] = meta.get("analyzer_results", [])

    detail = {
        "translated": translated,
        "translated_excerpt": translated[:300] + ("..." if len(translated) > 300 else ""),
        "status_code": resp.status_code,
        "elapsed": elapsed,
        "meta": {k: meta.get(k) for k in ("level", "deployable", "manual_review_required", "capability_gaps", "analyzer_results")},
        "validation": {k: result.get(k) for k in ("valid", "level", "deployable", "manual_review_required", "errors", "warnings") if k in result},
        "analyzer_findings": _summarize_analyzers(result.get("result", {}).get("analyzer_results", [])),
    }

    check_errors = check_translated(case, translated, meta)

    if check_errors:
        return {"status": "fail", "errors": check_errors, "elapsed": elapsed, "detail": detail}

    return {"status": "pass", "elapsed": elapsed, "translated_len": len(translated), "detail": detail}


def run_cache_hit_test(case, api_base):
    """Run translation twice; verify second call is faster."""
    import requests
    session = requests.Session()
    session.trust_env = False
    session.proxies = {"http": "", "https": ""}

    payload = {
        "config_text": case["source_config"],
        "from_vendor": case["source_vendor"],
        "to_vendor": case["target_vendor"],
        "source_domain": case["source_domain"],
        "target_domain": case["target_domain"],
        "source_platform": case.get("source_platform", ""),
        "target_platform": case.get("target_platform", ""),
    }

    try:
        t0 = time.time()
        r1 = session.post(f"{api_base}/api/translate", json=payload, timeout=REQUEST_TIMEOUT)
        t1 = time.time()
        r2 = session.post(f"{api_base}/api/translate", json=payload, timeout=REQUEST_TIMEOUT)
        t2 = time.time()
    except Exception as e:
        return {"status": "error", "error": str(e)}

    if r1.status_code != 200 or r2.status_code != 200:
        return {"status": "fail", "error": "translation failed during cache test"}

    first = t1 - t0
    second = t2 - t1
    speedup = first / max(second, 0.001)

    return {
        "status": "pass" if speedup >= 2 else "cache_miss",
        "first_ms": round(first * 1000),
        "second_ms": round(second * 1000),
        "speedup": round(speedup, 2),
    }


def generate_report(results, cases, filtered, tier_stats):
    lines = [
        "# Benchmark Coverage Report",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total cases: {len(cases)}",
        f"Filter: {'/'.join(filtered) if filtered else 'none'}",
        "",
        "## Tier Distribution",
        "",
    ]
    for tier in ("smoke", "core", "full"):
        s = tier_stats.get(tier, {})
        lines.append(f"- **{tier}**: {s.get('total', 0)} cases, static {s.get('static_pass', 0)}/{s.get('static_total', 0)}, live {s.get('live_pass', 0)}/{s.get('live_total', 0)}")

    lines += [
        "",
        "## Results",
        "",
        f"### Static",
        f"- Pass: {results['static']['pass']}",
        f"- Fail: {results['static']['fail']}",
        f"- Total: {results['static']['total']}",
        "",
        f"### Live",
        f"- Pass: {results['live']['pass']}",
        f"- Fail: {results['live']['fail']}",
        f"- Skip: {results['live']['skip']}",
        f"- Cache: {results.get('cache', {}).get('pass', 0)} pass / {results.get('cache', {}).get('fail', 0)} fail / {results.get('cache', {}).get('miss', 0)} miss",
        "",
        "## Case List",
        "",
        "| # | Name | Tier | Domain | Source->Target | Risk | Features | Static | Live | Elapsed |",
        "|---|------|------|--------|---------------|------|----------|--------|------|---------|",
    ]

    for idx, c in enumerate(cases, 1):
        sr = c.get("_static_result", "?")
        lr = c.get("_live_result", "?")
        el = c.get("_elapsed_ms", "")
        feat_str = ",".join(c["features"])
        lines.append(
            f"| {idx} | {c['name']} | {c['_tier']} | {c['source_domain']} | "
            f"{c['source_vendor']} -> {c['target_vendor']} | {c['risk']} | "
            f"{feat_str} | {sr} | {lr} | {el} |"
        )

    lines += ["", "## Domain Distribution", ""]
    domains = Counter(c["source_domain"] for c in cases)
    for d, cnt in sorted(domains.items()):
        lines.append(f"- {d}: {cnt}")
    lines.append("")

    all_features = set()
    for c in cases:
        all_features.update(c["features"])
    lines.append("## Feature Coverage")
    lines.append("")
    for f in sorted(all_features):
        lines.append(f"- {f}")

    out_path = PROJECT_ROOT / "docs" / "coverage" / "benchmark_coverage.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n")
    print(f"\nReport: {out_path}")


def print_summary(results, tier_stats):
    print(f"\n{'='*60}")
    print("Results")
    print(f"{'='*60}")
    print(f"Static: {results['static']['pass']}/{results['static']['total']} pass, {results['static']['fail']} fail")
    l = results['live']
    print(f"Live:   {l['pass']}/{l['pass']+l['fail']} pass, {l['fail']} fail, {l['skip']} skip")
    c = results.get('cache', {})
    if c.get('total', 0) > 0:
        print(f"Cache:  {c['pass']}/{c['total']} pass, {c['fail']} fail, {c['miss']} miss")

    for tier in ("smoke", "core", "full"):
        s = tier_stats.get(tier, {})
        if s.get("total", 0) > 0:
            sp = s.get("static_pass", 0)
            st = s.get("static_total", 0)
            lp = s.get("live_pass", 0)
            lt = s.get("live_total", 0)
            print(f"  [{tier}] static {sp}/{st} live {lp}/{lt}")


def main():
    parser = argparse.ArgumentParser(description="Benchmark case runner")
    parser.add_argument("--tier", choices=["smoke", "core", "full"], help="Filter by tier")
    parser.add_argument("--domain", help="Filter by source domain")
    parser.add_argument("--vendor", help="Filter by source vendor")
    parser.add_argument("--feature", help="Filter by feature")
    parser.add_argument("--static-only", action="store_true", help="Skip live API checks")
    parser.add_argument("--api-base", default=os.environ.get("BENCH_API_BASE", "http://127.0.0.1:5008"))
    parser.add_argument("--no-corpus", action="store_true", help="Exclude corpus-derived bench cases")
    parser.add_argument("--corpus-only", action="store_true", help="Only corpus-derived bench cases")
    parser.add_argument("--generate-report", action="store_true", help="Generate benchmark_coverage.md")
    parser.add_argument("--cache-test", type=int, nargs="?", const=1, default=0,
                        help="Run cache hit test on N cases (default: 1)")
    parser.add_argument("--live-report-json", type=str, default="",
                        help="Path to write per-case live results as JSON")
    args = parser.parse_args()

    os.environ["BENCH_API_BASE"] = args.api_base

    schema = load_schema()
    cases = discover_cases(tier=args.tier, domain=args.domain, vendor=args.vendor, feature=args.feature)

    if args.no_corpus:
        before = len(cases)
        cases = [c for c in cases if "corpus_ref" not in c]
        print(f"  --no-corpus: {before} -> {len(cases)} cases")

    if args.corpus_only:
        before = len(cases)
        cases = [c for c in cases if "corpus_ref" in c]
        print(f"  --corpus-only: {before} -> {len(cases)} cases")

    if not cases:
        print("No cases found matching filters.")
        sys.exit(1)

    print(f"Benchmark Runner — {len(cases)} cases, tier={args.tier or 'all'}\n")

    # State
    global RESULTS
    RESULTS = {"static": {"pass": 0, "fail": 0, "total": 0}, "live": {"pass": 0, "fail": 0, "skip": 0}, "cache": {"pass": 0, "fail": 0, "miss": 0, "total": 0}}
    tier_stats: dict = {}

    # Static
    print(f"{'='*60}")
    print(f"Static Validation ({len(cases)} cases)")
    print(f"{'='*60}")
    for c in cases:
        t = c["_tier"]
        tier_stats.setdefault(t, {"total": 0, "static_pass": 0, "static_fail": 0, "static_total": 0, "live_pass": 0, "live_fail": 0, "live_total": 0, "live_skip": 0})
        tier_stats[t]["total"] += 1

        err = validate_schema(c, schema)
        if err:
            print(f"  FAIL [schema] {c['_path']}: {err}")
            c["_static_result"] = "FAIL(schema)"
            RESULTS["static"]["fail"] += 1
            tier_stats[t]["static_fail"] += 1
        else:
            static_errs = run_static(c)
            if static_errs:
                for e in static_errs:
                    print(f"  FAIL [static] {c['_path']}: {e}")
                c["_static_result"] = "FAIL"
                RESULTS["static"]["fail"] += 1
                tier_stats[t]["static_fail"] += 1
            else:
                c["_static_result"] = "PASS"
                RESULTS["static"]["pass"] += 1
                tier_stats[t]["static_pass"] += 1
        RESULTS["static"]["total"] += 1
        tier_stats[t]["static_total"] += 1

    # Live
    print(f"\n{'='*60}")
    print(f"Live Translation ({len(cases)} cases)")
    print(f"{'='*60}")

    has_api_key = bool(os.environ.get("LLM_API_KEY"))
    if not has_api_key:
        try:
            from llm_settings import get_current_settings
            has_api_key = bool(get_current_settings().get("api_key"))
        except Exception:
            pass
    api_available = False
    if not args.static_only and has_api_key:
        import requests
        try:
            sess = requests.Session()
            sess.trust_env = False
            r = sess.get(f"{args.api_base}/healthz", timeout=5, proxies={"http": "", "https": ""})
            api_available = r.status_code == 200
        except Exception:
            pass

    run_live_checks = not args.static_only and api_available and has_api_key
    live_results_detail = []

    for c in cases:
        t = c["_tier"]
        if not run_live_checks:
            c["_live_result"] = "SKIP"
            c["_elapsed_ms"] = ""
            RESULTS["live"]["skip"] += 1
            tier_stats[t]["live_skip"] += 1
            if c == cases[0]:
                reason = "no LLM_API_KEY" if not has_api_key else "API unreachable" if not api_available else "static-only"
                print(f"  SKIP (all): {reason}")
            live_results_detail.append({
                "name": c["name"],
                "path": c["_path"],
                "tier": c["_tier"],
                "status": "skip",
                "elapsed_ms": "",
                "errors": [],
                "detail": {},
            })
            continue

        result = run_live(c)
        tier_stats[t]["live_total"] += 1

        # Detect unsafe_success: translation passes quality check but deployability
        # expectation is violated (manual_review_required=True or high-risk
        # deployable=true when it should be false)
        exp = c.get("expected", {})
        meta = result.get("detail", {}).get("meta", {})
        is_unsafe = (
            result["status"] == "pass"
            and exp.get("manual_review_required") is True
            and meta.get("manual_review_required") is True
            and meta.get("deployable") is True
            and exp.get("deployable") is False
        )
        if is_unsafe:
            result["status"] = "unsafe_success"
            result["category"] = "unsafe_success"

        if result["status"] == "pass":
            c["_live_result"] = "PASS"
            c["_elapsed_ms"] = f"{result['elapsed']*1000:.0f}"
            RESULTS["live"]["pass"] += 1
            tier_stats[t]["live_pass"] += 1
            print(f"  PASS {c['_path']} ({result['elapsed']:.1f}s, {result['translated_len']}B) [{t}]")
        elif result["status"] == "unsafe_success":
            c["_live_result"] = "UNSAFE"
            c["_elapsed_ms"] = f"{result['elapsed']*1000:.0f}"
            RESULTS["live"]["fail"] += 1
            tier_stats[t]["live_fail"] += 1
            print(f"  UNSAFE_SUCCESS {c['_path']}: deployable=True but manual_review_required=True required")
        else:
            c["_live_result"] = "FAIL"
            c["_elapsed_ms"] = f"{result['elapsed']*1000:.0f}"
            RESULTS["live"]["fail"] += 1
            tier_stats[t]["live_fail"] += 1
            category = result.get("category", "")
            if category:
                label = category.upper()
            else:
                label = "FAIL"
            err_msg = result.get("error") or "; ".join(result.get("errors", []))
            print(f"  {label} {c['_path']}: {err_msg} ({result['elapsed']:.1f}s)")
            detail = result.get("detail", {})
            if detail:
                excerpt = detail.get("translated_excerpt", "")
                if excerpt:
                    print(f"        excerpt: {excerpt}")
                meta = detail.get("meta", {})
                if meta:
                    print(f"        meta: {json.dumps(meta)}")
                val = detail.get("validation", {})
                if val.get("errors"):
                    print(f"        validation errors: {val['errors'][:3]}")
                if val.get("warnings"):
                    print(f"        validation warnings: {val['warnings'][:3]}")
                af = detail.get("analyzer_findings", {})
                if af:
                    print(f"        analyzer risks: {json.dumps(af)}")

        live_results_detail.append({
            "name": c["name"],
            "path": c["_path"],
            "tier": c["_tier"],
            "status": result["status"],
            "category": result.get("category", ""),
            "elapsed_ms": c["_elapsed_ms"],
            "errors": result.get("errors", []) if result["status"] != "pass" else [],
            "meta": result.get("detail", {}).get("meta", {}),
            "detail": result.get("detail", {}),
        })

    # Cache test
    if run_live_checks and args.cache_test > 0 and cases:
        print(f"\n{'='*60}")
        print(f"Cache Hit Test ({min(args.cache_test, len(cases))} case(s))")
        print(f"{'='*60}")
        for c in cases[:args.cache_test]:
            cr = run_cache_hit_test(c, args.api_base)
            RESULTS["cache"]["total"] += 1
            if cr["status"] == "pass":
                RESULTS["cache"]["pass"] += 1
                print(f"  PASS {c['_path']}: first={cr['first_ms']}ms second={cr['second_ms']}ms ({cr['speedup']}x)")
            elif cr["status"] == "cache_miss":
                RESULTS["cache"]["miss"] += 1
                print(f"  MISS {c['_path']}: first={cr['first_ms']}ms second={cr['second_ms']}ms ({cr['speedup']}x) < 2x")
            else:
                RESULTS["cache"]["fail"] += 1
                print(f"  FAIL {c['_path']}: {cr.get('error')}")

    print_summary(RESULTS, tier_stats)

    if args.live_report_json and live_results_detail:
        report_path = Path(args.live_report_json)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps({
            "summary": {
                "static": RESULTS["static"],
                "live": RESULTS["live"],
                "cache": RESULTS.get("cache", {}),
                "tier_stats": tier_stats,
            },
            "cases": live_results_detail,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nLive report JSON: {report_path}")

    if args.generate_report:
        fp = '|'.join([args.tier or '', args.domain or '', args.vendor or '', args.feature or ''])
        generate_report(RESULTS, cases, [args.tier or '', args.domain or '', args.vendor or '', args.feature or ''], tier_stats)

    return RESULTS["static"]["fail"] == 0 and RESULTS["live"]["fail"] == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
