"""Tests for scripts/evaluate_corpus_fallback.py"""

import json
import os
import re
import sys
import subprocess

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
EVAL_SCRIPT = os.path.join(PROJECT_ROOT, "scripts", "evaluate_corpus_fallback.py")
MD_REPORT = os.path.join(REPORTS_DIR, "CORPUS_FALLBACK_EVAL.md")
JSON_REPORT = os.path.join(REPORTS_DIR, "corpus_fallback_eval.json")

_eval_result = None


def _run_eval():
    global _eval_result
    if _eval_result is not None:
        return _eval_result
    result = subprocess.run(
        [sys.executable, EVAL_SCRIPT],
        capture_output=True, text=True,
        cwd=PROJECT_ROOT,
        env={**os.environ, "PYTHONPATH": PROJECT_ROOT},
    )
    _eval_result = result
    return result


# ---------------------------------------------------------------------------
# JSON report tests
# ---------------------------------------------------------------------------

def test_evaluator_runs_without_error():
    result = _run_eval()
    assert result.returncode == 0, f"stderr:\n{result.stderr}"


def test_evaluator_uses_sanitized_samples_path():
    result = _run_eval()
    assert result.returncode == 0
    with open(EVAL_SCRIPT) as f:
        content = f.read()
    assert "sanitized_samples" in content
    # Ensure no bare "corpus/samples" reference (not as part of "corpus/sanitized_samples")
    import re
    bare_refs = re.findall(r"corpus/samples[^/]", content)
    assert not bare_refs, f"Found bare corpus/samples references: {bare_refs}"


def test_evaluator_writes_json():
    _run_eval()
    assert os.path.exists(JSON_REPORT)
    with open(JSON_REPORT) as f:
        data = json.load(f)
    assert "summary" in data
    assert "results" in data


def test_evaluator_summary_fields():
    _run_eval()
    with open(JSON_REPORT) as f:
        data = json.load(f)
    s = data["summary"]
    for field in ("total", "passed", "failed", "pass_rate", "by_domain", "by_vendor"):
        assert field in s, f"Missing field: {field}"
    assert s["total"] > 0


def test_evaluator_all_samples_covered():
    _run_eval()
    manifest_path = os.path.join(PROJECT_ROOT, "corpus", "sanitized_samples", "manifest.json")
    with open(manifest_path) as f:
        manifest = json.load(f)
    with open(JSON_REPORT) as f:
        data = json.load(f)

    expected_pairs = set()
    for s in manifest["samples"]:
        for t in s["target_candidates"]:
            expected_pairs.add((s["id"], t))
    actual_pairs = set((r["sample_id"], r["target_vendor"]) for r in data["results"])
    missing_pairs = expected_pairs - actual_pairs
    assert not missing_pairs, f"Missing pairs: {missing_pairs}"


def test_evaluator_result_fields():
    _run_eval()
    with open(JSON_REPORT) as f:
        data = json.load(f)
    required = [
        "sample_id", "source_vendor", "target_vendor", "source_domain",
        "passed", "manual_review_ok", "missing_manual_review",
        "residue_ok", "found_residue",
        "secret_ok", "leaked_secrets",
        "missing_translations",
    ]
    for r in data["results"]:
        for field in required:
            assert field in r, f"Field '{field}' missing in result for {r.get('sample_id', '?')}"
    assert data["results"][0]["secret_ok"] is True


# ---------------------------------------------------------------------------
# Markdown report tests
# ---------------------------------------------------------------------------

def test_md_report_exists():
    _run_eval()
    assert os.path.exists(MD_REPORT)


def test_md_report_summary_numbers():
    _run_eval()
    with open(MD_REPORT) as f:
        content = f.read()
    with open(JSON_REPORT) as f:
        data = json.load(f)
    s = data["summary"]
    assert str(s["total"]) in content, "total not found in markdown"
    assert str(s["passed"]) in content, "passed not found in markdown"
    assert str(s["failed"]) in content, "failed not found in markdown"
    assert f"{s['pass_rate']}%" in content, "pass rate not found in markdown"
    assert "Secret leak count" in content, "secret leak declaration missing"
    assert "P0 risk" in content, "P0 risk declaration missing"
    assert "No P0 blocking issue identified" in content, "P0 risk value wrong"


def test_md_report_by_domain():
    _run_eval()
    with open(MD_REPORT) as f:
        content = f.read()
    assert "## By Domain" in content
    for domain in ("SWITCH", "ROUTER", "FIREWALL"):
        assert domain in content, f"Domain {domain} missing from markdown"


def test_md_report_by_vendor():
    _run_eval()
    with open(MD_REPORT) as f:
        content = f.read()
    assert "## By Vendor" in content
    for vendor in ("cisco", "huawei", "h3c", "ruijie", "huawei_usg", "hillstone", "topsec", "dptech"):
        assert vendor in content, f"Vendor {vendor} missing from markdown"


def test_md_report_failed_pairs_table():
    _run_eval()
    with open(MD_REPORT) as f:
        content = f.read()
    assert "## Failed Pairs" in content
    assert "sample_id" in content
    assert "source_vendor" in content
    assert "target_vendor" in content
    assert "forbidden_residue_hits" in content
    assert "notes" in content


def test_md_report_no_plaintext_secrets():
    _run_eval()
    sensitive_patterns = [
        re.compile(r"(?<![<>\w])(password|secret|cipher|shared-key)\s+\S+", re.I),
    ]
    with open(MD_REPORT) as f:
        content = f.read()
    for idx, pat in enumerate(sensitive_patterns):
        matches = pat.findall(content)
        # Exclude the known header "Secret leak count" which uses "Secret" as a label
        filtered = [m for m in matches if m.lower().strip() not in ("secret", "password")]
        assert not filtered, f"Found potential sensitive content in markdown (pattern {idx}): {filtered}"


def test_md_report_no_overclaim():
    _run_eval()
    forbidden_phrases = [
        "production ready without review",
        "fully supported",
        "100% coverage",
        "no issues",
    ]
    with open(MD_REPORT) as f:
        content = f.read()
    content_lower = content.lower()
    for phrase in forbidden_phrases:
        assert phrase not in content_lower, f"Overclaim phrase found: '{phrase}'"


def test_md_report_declaration():
    _run_eval()
    with open(MD_REPORT) as f:
        content = f.read()
    assert "fallback translator" in content.lower()
    assert "deterministic" in content.lower()
    assert "not" in content.lower() and "production" in content.lower()


def test_md_report_references_json():
    _run_eval()
    with open(MD_REPORT) as f:
        content = f.read()
    assert "corpus_fallback_eval.json" in content
