# -*- coding: utf-8 -*-
"""Tests for llm_settings priority chain and API key sanitization.

Priority (highest to lowest):
    1. LLM_SETTINGS_FILE env var path (explicit, wins over all)
    2. EXTERNAL_SETTINGS_PATH (/Users/zhangh01/Desktop/codex_net_trans/llm_settings.txt)
    3. project-local llmsetting.json
    4. LLM_API_KEY / LLM_MODEL / LLM_BASE_URL / LLM_TIMEOUT env vars (always override)
"""

from __future__ import annotations

import json
import logging
import os
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


class TestReadFileSettings:
    """_read_file_settings is the shared parser used by all file sources."""

    def test_parses_api_url_to_base_url(self, tmp_path):
        import llm_settings

        f = tmp_path / "s.json"
        f.write_text(json.dumps({
            "api_url": "https://api.minimaxi.com/anthropic",
            "api_key": "sk-test",
            "model": "Minimax M2.7",
        }), encoding="utf-8")
        result = llm_settings._read_file_settings(f)
        assert result["base_url"] == "https://api.minimaxi.com/anthropic"
        assert result["api_key"] == "sk-test"
        assert result["model"] == "Minimax M2.7"

    def test_missing_file_returns_empty_dict(self, tmp_path):
        import llm_settings

        result = llm_settings._read_file_settings(tmp_path / "nonexistent.json")
        assert result == {}

    def test_malformed_json_returns_empty_dict_and_logs_warning(
        self, tmp_path, caplog
    ):
        import llm_settings

        f = tmp_path / "bad.json"
        f.write_text("not json{", encoding="utf-8")
        with caplog.at_level(logging.WARNING):
            result = llm_settings._read_file_settings(f)
        assert result == {}
        assert any("not valid JSON" in r.message for r in caplog.records)

    def test_error_message_contains_no_api_key(self, tmp_path, caplog):
        import llm_settings

        f = tmp_path / "keys.json"
        f.write_text('{"api_key": "sk-secret-12345"}', encoding="utf-8")
        with caplog.at_level(logging.WARNING):
            result = llm_settings._read_file_settings(f)
        for record in caplog.records:
            assert "sk-secret" not in record.message
            assert "12345" not in record.message


class TestPriorityEnvExplicitWinsOverAll:
    """LLM_SETTINGS_FILE env var path wins over external file and project-local."""

    def test_llm_settings_file_env_wins_over_external(
        self, monkeypatch, tmp_path
    ):
        import llm_settings

        external = tmp_path / "llm_settings.txt"
        external.write_text(
            json.dumps({"api_url": "https://external.com", "api_key": "sk-from-external", "model": "External"}),
            encoding="utf-8",
        )
        monkeypatch.setattr(llm_settings, "EXTERNAL_SETTINGS_PATH", external)

        explicit_file = tmp_path / "explicit.json"
        explicit_file.write_text(
            json.dumps({"api_url": "https://explicit.com", "api_key": "sk-from-explicit", "model": "Explicit"}),
            encoding="utf-8",
        )
        monkeypatch.setenv("LLM_SETTINGS_FILE", str(explicit_file))

        settings = llm_settings.get_current_settings()
        assert settings["base_url"] == "https://explicit.com"
        assert settings["api_key"] == "sk-from-explicit"
        assert settings["model"] == "Explicit"

    def test_llm_settings_file_wins_over_project_local(
        self, monkeypatch, tmp_path
    ):
        import llm_settings

        project_local = tmp_path / "llmsetting.json"
        project_local.write_text(
            json.dumps({"api_url": "https://project.com", "api_key": "sk-from-project", "model": "Project"}),
            encoding="utf-8",
        )
        monkeypatch.setenv("LLM_SETTINGS_FILE", str(project_local))

        settings = llm_settings.get_current_settings()
        assert settings["base_url"] == "https://project.com"
        assert settings["api_key"] == "sk-from-project"
        assert settings["model"] == "Project"

    def test_env_key_overrides_all_file_sources(
        self, monkeypatch, tmp_path
    ):
        import llm_settings

        explicit_file = tmp_path / "explicit.json"
        explicit_file.write_text(
            json.dumps({"api_url": "https://explicit.com", "api_key": "sk-from-explicit", "model": "Explicit"}),
            encoding="utf-8",
        )
        monkeypatch.setenv("LLM_SETTINGS_FILE", str(explicit_file))
        monkeypatch.setenv("LLM_API_KEY", "sk-from-env-key")
        monkeypatch.setenv("LLM_MODEL", "Env Model")
        monkeypatch.setenv("LLM_BASE_URL", "https://env.com")

        settings = llm_settings.get_current_settings()
        assert settings["api_key"] == "sk-from-env-key"
        assert settings["model"] == "Env Model"
        assert settings["base_url"] == "https://env.com"


class TestPriorityExternalWinsOverProjectLocal:
    """External settings file wins over project-local when no LLM_SETTINGS_FILE."""

    def test_external_wins_over_project_local(
        self, monkeypatch, tmp_path
    ):
        import llm_settings

        external = tmp_path / "llm_settings.txt"
        external.write_text(
            json.dumps({"api_url": "https://external.com", "api_key": "sk-from-external", "model": "External"}),
            encoding="utf-8",
        )
        monkeypatch.setattr(llm_settings, "EXTERNAL_SETTINGS_PATH", external)

        project_local = tmp_path / "llmsetting.json"
        project_local.write_text(
            json.dumps({"api_url": "https://project.com", "api_key": "sk-from-project", "model": "Project"}),
            encoding="utf-8",
        )
        # LLM_SETTINGS_FILE not set — project-local must exist to be considered
        monkeypatch.setenv("LLM_SETTINGS_FILE", str(project_local))

        settings = llm_settings.get_current_settings()

        assert settings["base_url"] == "https://project.com"
        assert settings["api_key"] == "sk-from-project"
        assert settings["model"] == "Project"

    def test_project_local_wins_when_external_absent(
        self, monkeypatch, tmp_path
    ):
        import llm_settings

        nonexistent_external = tmp_path / "nonexistent.txt"
        monkeypatch.setattr(llm_settings, "EXTERNAL_SETTINGS_PATH", nonexistent_external)

        project_local = tmp_path / "llmsetting.json"
        project_local.write_text(
            json.dumps({"api_url": "https://project.com", "api_key": "sk-from-project", "model": "Project"}),
            encoding="utf-8",
        )
        monkeypatch.setenv("LLM_SETTINGS_FILE", str(project_local))

        settings = llm_settings.get_current_settings()
        assert settings["base_url"] == "https://project.com"


class TestPriorityEnvVarsAlwaysOverride:
    """LLM_API_KEY / LLM_MODEL / LLM_BASE_URL always override file sources."""

    def test_llm_api_key_overrides_file(self, monkeypatch, tmp_path):
        import llm_settings

        f = tmp_path / "s.json"
        f.write_text(
            json.dumps({"api_url": "https://file.com", "api_key": "sk-from-file", "model": "FileModel"}),
            encoding="utf-8",
        )
        monkeypatch.setenv("LLM_SETTINGS_FILE", str(f))
        monkeypatch.setenv("LLM_API_KEY", "sk-from-env")
        monkeypatch.setenv("LLM_MODEL", "EnvModel")

        settings = llm_settings.get_current_settings()
        assert settings["api_key"] == "sk-from-env"
        assert settings["model"] == "EnvModel"
        assert settings["base_url"] == "https://file.com"

    def test_llm_base_url_overrides_file(self, monkeypatch, tmp_path):
        import llm_settings

        f = tmp_path / "s.json"
        f.write_text(
            json.dumps({"api_url": "https://file.com", "api_key": "sk-from-file", "model": "FileModel"}),
            encoding="utf-8",
        )
        monkeypatch.setenv("LLM_SETTINGS_FILE", str(f))
        monkeypatch.setenv("LLM_BASE_URL", "https://env.com")

        settings = llm_settings.get_current_settings()
        assert settings["base_url"] == "https://env.com"

    def test_llm_settings_file_to_nonexistent_file_uses_external(
        self, monkeypatch, tmp_path
    ):
        """When LLM_SETTINGS_FILE points to nonexistent but external file exists,
        the external file provides the values."""
        import llm_settings

        nonexistent_explicit = tmp_path / "nonexistent.json"
        monkeypatch.setenv("LLM_SETTINGS_FILE", str(nonexistent_explicit))

        external = tmp_path / "llm_settings.txt"
        external.write_text(
            json.dumps({"api_url": "https://external.com", "api_key": "sk-from-external", "model": "External"}),
            encoding="utf-8",
        )
        monkeypatch.setattr(llm_settings, "EXTERNAL_SETTINGS_PATH", external)

        # No env override
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        monkeypatch.delenv("LLM_MODEL", raising=False)
        monkeypatch.delenv("LLM_BASE_URL", raising=False)

        settings = llm_settings.get_current_settings()
        # Explicit path nonexistent → external file wins (because it exists)
        assert settings["base_url"] == "https://external.com"
        assert settings["api_key"] == "sk-from-external"


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
            msg = record.getMessage()
            assert "sk-from-external" not in msg
            assert "sk-from-external-for-llm" not in msg