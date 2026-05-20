import pytest


def _make_fake_response(result_dict: dict):
    """Simulate the JSON response shape from /api/translate."""
    return {
        "ok": True,
        "request_id": "test-req-001",
        "version": "v11-test",
        "model": "test-model",
        "result": result_dict,
    }


def _extract_live_meta(response_json: dict) -> dict:
    """Extract live meta fields from /api/translate response.

    This replicates the extraction logic in bench/run_cases.py run_live().
    The critical invariant: all result fields read from response_json['result'].
    """
    result = response_json.get("result", {})
    validation = result.get("validation", {}) or {}
    meta = {
        "level": validation.get("level", ""),
        "deployable": validation.get("deployable"),
        "manual_review_required": validation.get("manual_review_required"),
        "capability_gaps": result.get("capability_gaps", []),
        "analyzer_results": result.get("analyzer_results", []),
    }
    return meta


def test_extract_live_meta_reads_nested_result():
    """All live meta fields must be read from result['result'], not top-level."""
    fake_resp = _make_fake_response({
        "translated": "sysname SW1",
        "validation": {"valid": True, "level": "info", "deployable": True, "manual_review_required": False, "warnings": [], "errors": []},
        "capability_gaps": [{"feature": "nat", "severity": "warning"}],
        "analyzer_results": [{"feature": "nat", "risk_level": "warning"}],
    })
    meta = _extract_live_meta(fake_resp)
    assert meta["deployable"] is True
    assert meta["manual_review_required"] is False
    assert len(meta["capability_gaps"]) == 1
    assert len(meta["analyzer_results"]) == 1
    assert meta["analyzer_results"][0]["feature"] == "nat"


def test_extract_live_meta_returns_empty_lists_when_missing():
    """Missing fields in nested result should return empty lists, not crash."""
    fake_resp = _make_fake_response({"translated": "sysname SW1"})
    meta = _extract_live_meta(fake_resp)
    assert meta["capability_gaps"] == []
    assert meta["analyzer_results"] == []


def test_extract_live_meta_does_not_read_top_level():
    """The bug: do NOT read capability_gaps/analyzer_results from top-level response."""
    fake_resp = _make_fake_response({
        "translated": "sysname SW1",
        "validation": {"valid": True, "level": "info", "deployable": True, "manual_review_required": False},
    })
    fake_resp["capability_gaps"] = [{"feature": "nat", "severity": "warning"}]
    fake_resp["analyzer_results"] = [{"feature": "nat", "risk_level": "warning"}]
    meta = _extract_live_meta(fake_resp)
    assert meta["capability_gaps"] == [], "Should read from nested result, not top-level"
    assert meta["analyzer_results"] == [], "Should read from nested result, not top-level"


def test_summarize_analyzers_returns_risk_summary():
    """_summarize_analyzers should only return non-info/non-none risks."""
    from bench.run_cases import _summarize_analyzers

    results = [
        {"feature": "nat", "risk_level": "warning", "rules": ["missing_inside"]},
        {"feature": "acl", "risk_level": "fatal", "rules": ["missing_reference"]},
        {"feature": "vlan", "risk_level": "info", "rules": []},
        {"feature": "system", "risk_level": "none", "rules": []},
    ]
    summary = _summarize_analyzers(results)
    assert "nat" in summary
    assert "acl" in summary
    assert "vlan" not in summary
    assert "system" not in summary
    assert summary["nat"]["risk"] == "warning"
    assert summary["acl"]["risk"] == "fatal"
