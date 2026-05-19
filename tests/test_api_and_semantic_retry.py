import pytest

pytest.importorskip("flask")

from core.graph import State
from core.graph.nodes import SemanticValidatorNode
from web_app import create_app


def test_semantic_validator_returns_informative_output():
    node = SemanticValidatorNode()
    state = State()
    state.set(
        "ir_translation",
        [
            {"type": "vlan", "translated_lines": ["vlan batch 10"], "original_lines": ["vlan 10"]},
            {"type": "interface", "translated_lines": [], "original_lines": ["interface Gi0/1"]},
        ],
    )
    state.set("ir_compare", {
        "overall_match": False,
        "matched_blocks": [
            {"type": "vlan", "match": True, "similarity": 0.6},
            {"type": "interface", "match": False, "similarity": 0.0},
        ],
    })

    result = node.execute(state)

    assert result.is_success()
    output = result.output
    assert output["score"] == 0.5
    assert output["matched_features"] == ["vlan"]
    assert output["missing_features"] == ["interface"]


def test_semantic_validator_detects_vendor_residue():
    node = SemanticValidatorNode()
    state = State()
    state.set(
        "ir_translation",
        [
            {"type": "interface", "translated_lines": ["interface GigabitEthernet0/1", " cisco-style command"], "original_lines": ["interface Gi0/1"]},
        ],
    )
    state.set("ir_compare", {"overall_match": True, "matched_blocks": [{"type": "interface", "match": True}]})
    state.set("from_vendor", "cisco")

    result = node.execute(state)

    assert result.is_success()
    output = result.output
    assert len(output.get("source_vendor_residue", [])) > 0


def test_semantic_validator_full_match_has_full_score():
    node = SemanticValidatorNode()
    state = State()
    state.set(
        "ir_translation",
        [
            {"type": "ospf", "translated_lines": ["ospf 1"], "original_lines": ["router ospf 1"]},
        ],
    )
    state.set("ir_compare", {"overall_match": True, "matched_blocks": [{"type": "ospf", "match": True}]})

    result = node.execute(state)

    assert result.is_success()
    assert result.output["score"] == 1.0
    assert result.output["missing_features"] == []


def test_health_and_readiness_endpoints():
    app = create_app()
    client = app.test_client()

    health = client.get("/healthz")
    ready = client.get("/readyz")

    assert health.status_code == 200
    assert ready.status_code == 200
    assert health.json["ok"] is True
    assert ready.json["ok"] is True


def test_api_translate_validates_empty_payload():
    app = create_app()
    client = app.test_client()

    resp = client.post("/api/translate", json={"config_text": "", "to_vendor": "huawei"})
    assert resp.status_code == 400
    assert resp.json["error_code"] == "EMPTY_CONFIG"


def test_api_translate_returns_structured_result():
    app = create_app()
    client = app.test_client()
    resp = client.post(
        "/api/translate",
        json={
            "config_text": "hostname SW1\nvlan 10\n",
            "from_vendor": "cisco",
            "to_vendor": "huawei",
        },
    )
    assert resp.status_code == 200
    assert resp.json["ok"] is True
    assert "result" in resp.json
    assert "translated" in resp.json["result"]
    assert "fallback_used" in resp.json["result"]
