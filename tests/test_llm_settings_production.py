# -*- coding: utf-8 -*-
import json
import os
import stat


def test_save_settings_uses_configurable_private_settings_file(tmp_path, monkeypatch):
    import llm_settings

    settings_file = tmp_path / "llmsetting.json"
    monkeypatch.setenv("LLM_SETTINGS_FILE", str(settings_file))

    llm_settings.save_settings({
        "api_key": "secret-key",
        "model": "MiniMax-M2.7",
        "base_url": "https://api.minimaxi.com/anthropic",
        "timeout": 180,
    })

    saved = json.loads(settings_file.read_text(encoding="utf-8"))
    assert saved["api_key"] == "secret-key"
    assert saved["timeout"] == 180
    assert stat.S_IMODE(os.stat(settings_file).st_mode) == 0o600


def test_get_current_settings_survives_invalid_timeout(tmp_path, monkeypatch):
    import llm_settings

    settings_file = tmp_path / "llmsetting.json"
    settings_file.write_text(
        json.dumps({
            "api_key": "secret-key",
            "model": "MiniMax-M2.7",
            "base_url": "https://api.minimaxi.com/anthropic",
            "timeout": "bad",
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("LLM_SETTINGS_FILE", str(settings_file))
    monkeypatch.delenv("LLM_TIMEOUT", raising=False)

    settings = llm_settings.get_current_settings()

    assert settings["timeout"] == 45


def test_get_current_settings_clamps_env_timeout(tmp_path, monkeypatch):
    import llm_settings

    settings_file = tmp_path / "llmsetting.json"
    settings_file.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("LLM_SETTINGS_FILE", str(settings_file))
    monkeypatch.setenv("LLM_TIMEOUT", "9999")

    settings = llm_settings.get_current_settings()

    assert settings["timeout"] == 300
