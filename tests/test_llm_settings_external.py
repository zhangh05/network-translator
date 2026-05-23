# -*- coding: utf-8 -*-
"""Tests for llm_settings external file loading and API key sanitization."""

from __future__ import annotations

import json
import logging
import pytest


class TestMaskApiKey:
    """API key must never be logged in plain text."""

    def test_mask_api_key_returns_astrisk_only(self):
        from llm_settings import mask_api_key

        result = mask_api_key("sk-test-key-1234567890")
        assert result == "***"
        assert "sk-test" not in result
        assert "1234567890" not in result

    def test_mask_api_key_none_returns_not_set(self):
        from llm_settings import mask_api_key

        assert mask_api_key(None) == "(not set)"

    def test_mask_api_key_empty_returns_not_set(self):
        from llm_settings import mask_api_key

        assert mask_api_key("") == "(not set)"

    def test_mask_api_key_safe_alias(self):
        from llm_settings import mask_api_key_safe

        assert mask_api_key_safe("sk-abc") == "***"


class TestExternalSettingsFile:
    """External settings file loading with sanitized error messages."""

    def test_reads_api_url_as_base_url(self, monkeypatch, tmp_path):
        import llm_settings

        external = tmp_path / "llm_settings.txt"
        external.write_text(
            json.dumps({
                "api_url": "https://api.minimaxi.com/anthropic",
                "api_key": "sk-test-key-abcdef",
                "model": "Minimax M2.7",
            }),
            encoding="utf-8",
        )
        monkeypatch.setattr(llm_settings, "EXTERNAL_SETTINGS_PATH", external)

        result = llm_settings._read_external_settings()

        assert result["base_url"] == "https://api.minimaxi.com/anthropic"
        assert result["api_key"] == "sk-test-key-abcdef"
        assert result["model"] == "Minimax M2.7"

    def test_model_normalized_stripped(self, monkeypatch, tmp_path):
        import llm_settings

        external = tmp_path / "llm_settings.txt"
        external.write_text(
            json.dumps({"model": "  Minimax M2.7  "}),
            encoding="utf-8",
        )
        monkeypatch.setattr(llm_settings, "EXTERNAL_SETTINGS_PATH", external)

        result = llm_settings._read_external_settings()

        assert result["model"] == "Minimax M2.7"

    def test_missing_file_returns_empty_dict(self, monkeypatch, tmp_path):
        import llm_settings

        nonexistent = tmp_path / "nonexistent.txt"
        monkeypatch.setattr(llm_settings, "EXTERNAL_SETTINGS_PATH", nonexistent)

        result = llm_settings._read_external_settings()

        assert result == {}

    def test_malformed_json_returns_empty_dict_and_logs_warning(
        self, monkeypatch, tmp_path, caplog
    ):
        import llm_settings

        external = tmp_path / "llm_settings.txt"
        external.write_text("not valid json{", encoding="utf-8")
        monkeypatch.setattr(llm_settings, "EXTERNAL_SETTINGS_PATH", external)

        with caplog.at_level(logging.WARNING):
            result = llm_settings._read_external_settings()

        assert result == {}
        assert any("not valid JSON" in r.message for r in caplog.records)

    def test_empty_file_returns_empty_dict(self, monkeypatch, tmp_path):
        import llm_settings

        external = tmp_path / "llm_settings.txt"
        external.write_text("", encoding="utf-8")
        monkeypatch.setattr(llm_settings, "EXTERNAL_SETTINGS_PATH", external)

        result = llm_settings._read_external_settings()

        assert result == {}

    def test_error_message_contains_no_api_key(self, monkeypatch, tmp_path, caplog):
        import llm_settings

        external = tmp_path / "llm_settings.txt"
        external.write_text('{"api_key": "sk-secret-12345"}', encoding="utf-8")
        monkeypatch.setattr(llm_settings, "EXTERNAL_SETTINGS_PATH", external)

        with caplog.at_level(logging.WARNING):
            result = llm_settings._read_external_settings()

        for record in caplog.records:
            assert "sk-secret" not in record.message
            assert "12345" not in record.message


class TestPriorityResolution:
    """Priority: env var > external > project-local > env fallback."""

    def test_env_override_wins_over_external_file(
        self, monkeypatch, tmp_path
    ):
        import llm_settings

        external = tmp_path / "llm_settings.txt"
        external.write_text(
            json.dumps({
                "api_url": "https://external.example.com",
                "api_key": "sk-from-external",
                "model": "External Model",
            }),
            encoding="utf-8",
        )
        monkeypatch.setattr(llm_settings, "EXTERNAL_SETTINGS_PATH", external)
        monkeypatch.setenv("LLM_SETTINGS_FILE", str(tmp_path / "project.json"))

        monkeypatch.setenv("LLM_API_KEY", "sk-from-env")
        monkeypatch.setenv("LLM_MODEL", "Env Model")
        monkeypatch.setenv("LLM_BASE_URL", "https://env.example.com")

        settings = llm_settings.get_current_settings()

        assert settings["api_key"] == "sk-from-env"
        assert settings["model"] == "Env Model"
        assert settings["base_url"] == "https://env.example.com"

        monkeypatch.delenv("LLM_API_KEY")
        monkeypatch.delenv("LLM_MODEL")
        monkeypatch.delenv("LLM_BASE_URL")

    def test_external_wins_over_project_local(
        self, monkeypatch, tmp_path
    ):
        import llm_settings

        external = tmp_path / "llm_settings.txt"
        external.write_text(
            json.dumps({
                "api_url": "https://external.example.com",
                "api_key": "sk-from-external",
                "model": "External Model",
            }),
            encoding="utf-8",
        )
        monkeypatch.setattr(llm_settings, "EXTERNAL_SETTINGS_PATH", external)

        project_local = tmp_path / "llmsetting.json"
        project_local.write_text(
            json.dumps({
                "api_url": "https://project.example.com",
                "api_key": "sk-from-project",
                "model": "Project Model",
            }),
            encoding="utf-8",
        )
        monkeypatch.setenv("LLM_SETTINGS_FILE", str(project_local))

        settings = llm_settings.get_current_settings()

        assert settings["base_url"] == "https://external.example.com"
        assert settings["api_key"] == "sk-from-external"
        assert settings["model"] == "External Model"


class TestCreateLlmFromSettings:
    """create_llm_from_settings works with external file without logging the key."""

    def test_llm_created_with_external_key(self, monkeypatch, tmp_path, caplog):
        import llm_settings

        external = tmp_path / "llm_settings.txt"
        external.write_text(
            json.dumps({
                "api_url": "https://api.minimaxi.com/anthropic",
                "api_key": "sk-from-external-for-llm",
                "model": "Minimax M2.7",
                "timeout": 60,
            }),
            encoding="utf-8",
        )
        monkeypatch.setattr(llm_settings, "EXTERNAL_SETTINGS_PATH", external)
        monkeypatch.setenv("LLM_SETTINGS_FILE", str(tmp_path / "nonexistent.json"))

        llm = llm_settings.create_llm_from_settings()

        assert llm.api_key == "sk-from-external-for-llm"
        assert llm.base_url == "https://api.minimaxi.com/anthropic"
        assert llm.timeout == 60

        for record in caplog.records:
            assert "sk-from-external" not in record.getMessage()
            assert "sk-from-external-for-llm" not in record.getMessage()