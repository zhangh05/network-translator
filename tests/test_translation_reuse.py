# -*- coding: utf-8 -*-
"""Tests for translation reuse (config hash caching)."""

import hashlib
import pytest
from project_store import Project, ProjectStore


def test_project_stores_last_translate_hash():
    p = Project("test-id", "Test")
    assert hasattr(p, "last_translate_hash"), "Project must have last_translate_hash field"
    assert p.last_translate_hash == "", "Default last_translate_hash should be empty string"


def test_project_to_dict_includes_last_translate_hash():
    p = Project("test-id", "Test")
    p.last_translate_hash = "abc123"
    d = p.to_dict()
    assert "last_translate_hash" in d, "to_dict must include last_translate_hash"
    assert d["last_translate_hash"] == "abc123"


def test_project_from_data_restores_last_translate_hash():
    data = {
        "id": "test-id",
        "name": "Test",
        "config_text": "vlan 10",
        "last_translate_hash": "xyz789",
    }
    proj = ProjectStore._project_from_data("test-id", data)
    assert proj.last_translate_hash == "xyz789"


def test_identical_config_produces_identical_hash():
    config = "vlan 10\ninterface GigabitEthernet0/1"
    h1 = hashlib.md5(config.encode()).hexdigest()
    h2 = hashlib.md5(config.encode()).hexdigest()
    assert h1 == h2


def test_different_config_produces_different_hash():
    config1 = "vlan 10"
    config2 = "vlan 20"
    h1 = hashlib.md5(config1.encode()).hexdigest()
    h2 = hashlib.md5(config2.encode()).hexdigest()
    assert h1 != h2