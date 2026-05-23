# -*- coding: utf-8 -*-
import json
import os
import stat

from core.runtime_config import get_int_setting, is_private_file, write_private_json


def test_get_int_setting_uses_default_for_invalid_values(monkeypatch):
    monkeypatch.setenv("LLM_TIMEOUT", "not-a-number")

    assert get_int_setting("LLM_TIMEOUT", 45, minimum=1) == 45


def test_get_int_setting_clamps_to_minimum_and_maximum(monkeypatch):
    monkeypatch.setenv("LLM_TIMEOUT", "0")
    assert get_int_setting("LLM_TIMEOUT", 45, minimum=1) == 1

    monkeypatch.setenv("LLM_TIMEOUT", "9999")
    assert get_int_setting("LLM_TIMEOUT", 45, minimum=1, maximum=300) == 300


def test_write_private_json_is_atomic_and_owner_only(tmp_path):
    target = tmp_path / "llmsetting.json"

    write_private_json(target, {"api_key": "secret", "timeout": 180})

    assert json.loads(target.read_text(encoding="utf-8")) == {"api_key": "secret", "timeout": 180}
    mode = stat.S_IMODE(os.stat(target).st_mode)
    assert mode == 0o600
    assert is_private_file(target) is True


def test_is_private_file_rejects_group_or_world_permissions(tmp_path):
    target = tmp_path / "llmsetting.json"
    target.write_text("{}", encoding="utf-8")
    os.chmod(target, 0o644)

    assert is_private_file(target) is False
