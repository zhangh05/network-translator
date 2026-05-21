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


# ═══════════════════════════════════════════════════════════════════
# check_translated — capability gap pass/fail alignment
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture
def _base_case():
    return {
        "name": "test",
        "features": ["nat"],
        "source_config": "some config",
        "risk": "high",
        "expected": {
            "deployable": False,
            "manual_review_required": True,
            "no_markdown_fence": True,
            "no_placeholder": True,
            "max_level": "error",
        },
    }


class TestCapabilityGapPassFail:
    def test_expected_non_deployable_with_cap_gap_passes(self, _base_case):
        """expected dep=false/mrr=true + actual dep=false/mrr=true + cap gap → PASS."""
        from bench.run_cases import check_translated
        meta = {
            "deployable": False,
            "manual_review_required": True,
            "level": "warning",
            "capability_gaps": [{"feature": "ipsec", "severity": "warning", "status": "unknown"}],
        }
        errs = check_translated(_base_case, "some translated text", meta)
        assert len(errs) == 0, f"expected clean pass, got errors: {errs}"

    def test_expected_mrr_true_with_cap_gap_passes(self, _base_case):
        """expected mrr=true + actual mrr=true + cap gap → PASS (mrr check doesn't error)."""
        from bench.run_cases import check_translated
        meta = {
            "deployable": False,
            "manual_review_required": True,
            "level": "warning",
            "capability_gaps": [{"feature": "nat", "severity": "warning", "status": "unknown"}],
        }
        errs = check_translated(_base_case, "some translated text", meta)
        assert len(errs) == 0

    def test_expected_clean_deploy_with_cap_gap_fails(self):
        """expected dep=true/mrr=false but actual has cap gap → FAIL."""
        from bench.run_cases import check_translated
        case = {
            "name": "test",
            "features": ["nat"],
            "source_config": "some config",
            "risk": "high",
            "expected": {
                "deployable": True,
                "manual_review_required": False,
                "no_markdown_fence": True,
                "no_placeholder": True,
                "max_level": "warning",
            },
        }
        meta = {
            "deployable": True,
            "manual_review_required": False,
            "level": "warning",
            "capability_gaps": [{"feature": "nat", "severity": "warning", "status": "unknown"}],
        }
        errs = check_translated(case, "some translated text", meta)
        assert any("capability_gaps" in e for e in errs), f"expected cap gap error, got: {errs}"

    def test_fatal_cap_gap_fails_only_when_expected_clean(self, _base_case):
        """fatal capability gap fails only when annotation expects clean deploy."""
        from bench.run_cases import check_translated
        # Annotation expects non-deployable — fatal gap should NOT cause error
        case = dict(_base_case)
        case["expected"]["deployable"] = False
        case["expected"]["manual_review_required"] = True
        meta = {
            "deployable": False,
            "manual_review_required": True,
            "level": "error",
            "capability_gaps": [{"feature": "bgp", "severity": "fatal", "status": "unsupported"}],
        }
        errs = check_translated(case, "some translated text", meta)
        assert not any("capability_gaps" in e for e in errs), (
            f"fatal gap should not error when annotation expects non-deployable, got: {errs}"
        )

        # Annotation expects clean deployable — fatal gap SHOULD cause error
        case2 = dict(_base_case)
        case2["expected"]["deployable"] = True
        case2["expected"]["manual_review_required"] = False
        meta2 = {
            "deployable": True,
            "manual_review_required": False,
            "level": "info",
            "capability_gaps": [{"feature": "bgp", "severity": "fatal", "status": "unsupported"}],
        }
        errs2 = check_translated(case2, "some translated text", meta2)
        assert any("fatal capability_gaps" in e for e in errs2), (
            f"expected fatal gap error when clean deploy expected, got: {errs2}"
        )

    def test_missing_must_include_still_fails(self, _base_case):
        """must_include missing → FAIL regardless of cap gap alignment."""
        from bench.run_cases import check_translated
        case = dict(_base_case)
        case["expected"]["must_include"] = ["MUST_BE_PRESENT"]
        meta = {
            "deployable": False,
            "manual_review_required": True,
            "level": "warning",
            "capability_gaps": [{"feature": "ipsec", "severity": "warning", "status": "unknown"}],
        }
        errs = check_translated(case, "translated text without keyword", meta)
        assert any("must_include" in e for e in errs), f"expected must_include error, got: {errs}"

    def test_forbidden_pattern_still_fails(self, _base_case):
        """must_not_include forbidden → FAIL regardless of cap gap alignment."""
        from bench.run_cases import check_translated
        case = dict(_base_case)
        case["expected"]["must_not_include"] = ["forbidden-command"]
        meta = {
            "deployable": False,
            "manual_review_required": True,
            "level": "warning",
            "capability_gaps": [{"feature": "ipsec", "severity": "warning", "status": "unknown"}],
        }
        errs = check_translated(case, "forbidden-command in output", meta)
        assert any("forbidden" in e for e in errs), f"expected forbidden error, got: {errs}"
