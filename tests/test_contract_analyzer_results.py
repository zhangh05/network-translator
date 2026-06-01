import os
import json
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("flask")


def test_run_translation_returns_analyzer_results(monkeypatch):
    """P0-1: run_translation() must return analyzer_results in its dict."""
    import project_store

    class StubAgent:
        def run(self, **kwargs):
            return {
                "translated": "sysname SW1",
                "success": True,
                "analyzer_results": [],
            }

    monkeypatch.setattr(project_store, "_get_translation_agent", lambda: StubAgent())
    monkeypatch.setattr(project_store.TranslationSlotLimiter, "acquire", lambda self, **kwargs: _noop_context())

    from project_store import run_translation
    result = run_translation(
        config_text="hostname SW1\ninterface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n no shutdown\n",
        from_vendor="cisco",
        to_vendor="huawei",
    )
    assert "analyzer_results" in result, "analyzer_results missing from run_translation output"
    ar = result["analyzer_results"]
    assert isinstance(ar, list), "analyzer_results must be a list"


def test_api_returns_analyzer_results(monkeypatch):
    """P0-1: /api/translate response must include analyzer_results."""
    _stub_web_translate(monkeypatch, [{"feature": "interface", "risk_level": "info"}])

    from web_app import create_app
    app = create_app()
    client = app.test_client()
    resp = client.post("/api/translate", json={
        "config_text": "hostname R1\ninterface GigabitEthernet0/1\n ip address 192.168.1.1 255.255.255.0\n",
        "from_vendor": "cisco",
        "to_vendor": "huawei",
    })
    assert resp.status_code == 200
    body = resp.get_json()
    r = body.get("result", {})
    assert "analyzer_results" in r, "analyzer_results missing from /api/translate result"
    ar = r["analyzer_results"]
    assert isinstance(ar, list)


def test_api_with_nat_input_has_nonempty_analyzer_results(monkeypatch):
    """NAT input should produce non-empty analyzer_results with risk info."""
    _stub_web_translate(monkeypatch, [{"feature": "nat", "risk_level": "warning"}])

    from web_app import create_app
    app = create_app()
    client = app.test_client()
    config = """hostname FW1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 ip nat outside
!
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 ip nat inside
!
ip nat inside source list 100 interface GigabitEthernet0/0 overload
access-list 100 permit ip 192.168.1.0 0.0.0.255 any
"""
    resp = client.post("/api/translate", json={
        "config_text": config,
        "from_vendor": "cisco",
        "to_vendor": "huawei",
    })
    assert resp.status_code == 200
    body = resp.get_json()
    r = body.get("result", {})
    ar = r.get("analyzer_results", [])
    assert len(ar) > 0, "NAT config should produce analyzer results"
    features_found = {a.get("feature") for a in ar if isinstance(a, dict)}
    assert "nat" in features_found, "nat feature should appear in analyzer_results"


class _noop_context:
    def __enter__(self):
        return None

    def __exit__(self, exc_type, exc, tb):
        return False


def _stub_web_translate(monkeypatch, analyzer_results):
    import web_app

    def fake_run_translation(**kwargs):
        return {
            "translated": "sysname R1",
            "validation": {},
            "success": True,
            "analyzer_results": analyzer_results,
        }

    monkeypatch.setattr(web_app.project_store, "run_translation", fake_run_translation)


def test_analyzers_fatal_warning_detected():
    """Analyzer results with fatal/warning risk_level should be counted."""
    from web_app import create_app, _build_log_entry
    app = create_app()

    mock_result = {
        "success": False,
        "analyzer_results": [
            {"feature": "nat", "risk_level": "fatal", "status": "analyzed", "rules": [], "notes": ["Missing inside interface"]},
            {"feature": "acl", "risk_level": "warning", "status": "analyzed", "rules": [], "notes": []},
            {"feature": "vlan", "risk_level": "info", "status": "analyzed", "rules": [], "notes": []},
        ],
        "cache_hit": False,
        "fallback_used": False,
        "route_decision": "llm_success",
        "features": ["nat", "acl", "vlan"],
        "node_results": [],
        "capability_gaps": [],
        "validation": {"level": "fatal", "deployable": False, "manual_review_required": True, "warnings": [], "errors": ["NAT fatal"]},
    }

    entry = _build_log_entry(
        request_id="test-123",
        elapsed=0.5,
        config_text="hostname FW1\n",
        from_vendor="cisco",
        to_vendor="huawei",
        source_domain="routing",
        source_platform="ios",
        target_domain="routing",
        target_platform="vrp",
        result=mock_result,
        error=None,
    )

    assert "analyzer_results" in entry
    assert entry["analyzer_warning_count"] == 1
    assert entry["analyzer_fatal_count"] == 1
