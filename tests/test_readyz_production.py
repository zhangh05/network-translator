# -*- coding: utf-8 -*-
import json
import os


def test_readyz_reports_runtime_checks_and_insecure_settings_file(tmp_path, monkeypatch):
    from web_app import create_app

    settings_file = tmp_path / "llmsetting.json"
    settings_file.write_text(
        json.dumps({
            "api_key": "secret-key",
            "model": "MiniMax-M2.7",
            "base_url": "https://api.minimaxi.com/anthropic",
            "timeout": 180,
        }),
        encoding="utf-8",
    )
    os.chmod(settings_file, 0o644)
    monkeypatch.setenv("LLM_SETTINGS_FILE", str(settings_file))
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    client = create_app().test_client()
    resp = client.get("/readyz")

    assert resp.status_code == 200
    assert resp.json["ok"] is True
    assert resp.json["checks"]["llm_configured"] is True
    assert resp.json["checks"]["settings_file_private"] is False
    assert "llmsetting.json permissions allow group/world access" in resp.json["warnings"]


def test_readyz_reports_feature_registry_loaded(monkeypatch):
    from web_app import create_app

    monkeypatch.delenv("LLM_SETTINGS_FILE", raising=False)
    client = create_app().test_client()

    resp = client.get("/readyz")

    assert resp.status_code == 200
    assert resp.json["checks"]["feature_registry_loaded"] is True
