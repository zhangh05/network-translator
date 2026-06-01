"""Tests for docs/FALLBACK_GAP_ANALYSIS.md consistency with evaluator output."""

import json
import os
import re

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GAP_ANALYSIS_PATH = os.path.join(PROJECT_ROOT, "docs", "FALLBACK_GAP_ANALYSIS.md")
EVAL_JSON_PATH = os.path.join(PROJECT_ROOT, "reports", "corpus_fallback_eval.json")


def test_gap_analysis_exists():
    assert os.path.exists(GAP_ANALYSIS_PATH)


def test_gap_analysis_mentions_all_failing_pairs():
    assert os.path.exists(EVAL_JSON_PATH)
    with open(EVAL_JSON_PATH) as f:
        data = json.load(f)
    with open(GAP_ANALYSIS_PATH) as f:
        content = f.read()

    failing_pairs = set()
    for r in data["results"]:
        if not r["passed"]:
            failing_pairs.add((r["sample_id"], r["target_vendor"]))

    for sid, tgt in failing_pairs:
        assert sid in content, f"Gap analysis doc missing sample '{sid}'"
        assert tgt in content, f"Gap analysis doc missing target '{tgt}'"

    # Build gap → expected pairs from evaluator
    gap_pairs = {}
    for r in data["results"]:
        if not r["passed"]:
            sid, tgt = r["sample_id"], r["target_vendor"]
            gap_pairs[f"{sid} -> {tgt}"] = {"sample_id": sid, "target": tgt}

    lines = content.splitlines()
    for info in gap_pairs.values():
        sid_lines = [i for i, l in enumerate(lines) if info["sample_id"] in l]
        tgt_lines = [i for i, l in enumerate(lines) if info["target"] in l]
        within_30 = any(abs(si - ti) < 30 for si in sid_lines for ti in tgt_lines)
        assert within_30, \
            f"Sample '{info['sample_id']}' and target '{info['target']}' not found within 30 lines of each other"


def test_gap_analysis_summary_matches_eval():
    assert os.path.exists(EVAL_JSON_PATH)
    with open(EVAL_JSON_PATH) as f:
        data = json.load(f)
    with open(GAP_ANALYSIS_PATH) as f:
        content = f.read()

    s = data["summary"]
    patterns = [
        (str(s["total"]), "Total: 24 pairs mentioned"),
        (str(s["passed"]), "Passed count matches"),
        (str(s["failed"]), "Failed count matches"),
    ]
    for value, desc in patterns:
        assert value in content, f"Summary value {value} not found in doc ({desc})"


def test_gap_analysis_has_required_sections():
    with open(GAP_ANALYSIS_PATH) as f:
        content = f.read()
    for section in [
        "## Summary",
        "## Resolved in Batch M",
        "## Active Gap Register",
        "## Priority Summary",
        "### GAP-RT-01",
        "### GAP-FW-03",
    ]:
        assert section in content, f"Missing section: {section}"


def test_gap_analysis_no_known_regressions():
    """The gap analysis should not claim more active failures than the evaluator found."""
    with open(EVAL_JSON_PATH) as f:
        data = json.load(f)
    with open(GAP_ANALYSIS_PATH) as f:
        content = f.read()

    failed_count = data["summary"]["failed"]
    # Count active gap entries only (in Active Gap Register section, not in Resolved sections)
    # Split at "## Active Gap Register" and count GAP entries there
    active_section = content.split("## Active Gap Register", 1)[-1]
    # Stop at next ## heading if present
    active_section = re.split(r"\n## ", active_section)[0]
    gap_entries = re.findall(r"### GAP-\w+-\d+:", active_section)
    assert len(gap_entries) <= failed_count, \
        f"Doc has {len(gap_entries)} active gap entries but evaluator reports only {failed_count} failures"
