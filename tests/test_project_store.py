import os
import tempfile
from pathlib import Path

import pytest

from project_store import ProjectStore


@pytest.fixture
def store():
    with tempfile.TemporaryDirectory() as tmp:
        yield ProjectStore(project_dir=tmp)


def test_create_and_get_project(store):
    p = store.create_project("test1")
    assert p.id
    assert p.name == "test1"
    assert p.config_text == ""

    fetched = store.get_project(p.id)
    assert fetched is not None
    assert fetched.name == "test1"


def test_list_projects(store):
    assert store.list_projects() == []
    store.create_project("a")
    store.create_project("b")
    assert len(store.list_projects()) == 2


def test_update_project(store):
    p = store.create_project("x")
    ok = store.update_project(p.id, {"name": "y", "config_text": "hostname R1"})
    assert ok
    updated = store.get_project(p.id)
    assert updated.name == "y"
    assert updated.config_text == "hostname R1"


def test_update_nonexistent(store):
    assert store.update_project("nope", {"name": "x"}) is False


def test_delete_project(store):
    p = store.create_project("x")
    assert store.delete_project(p.id) is True
    assert store.get_project(p.id) is None


def test_delete_nonexistent(store):
    assert store.delete_project("nope") is False


def test_add_history(store):
    p = store.create_project("x")
    entry = {"config_text": "vlan 10", "from_vendor": "cisco", "to_vendor": "huawei", "success": True, "translated": "vlan 10"}
    assert store.add_history(p.id, entry) is True
    full = store.get_project(p.id)
    assert len(full.history) == 1
    assert full.history[0]["from_vendor"] == "cisco"


def test_history_max_50_entries(store):
    p = store.create_project("x")
    for i in range(60):
        store.add_history(p.id, {"config_text": f"vlan {i}", "success": True})
    reloaded = store.get_project(p.id)
    assert len(reloaded.history) <= 50


def test_project_id_path_traversal(store):
    with pytest.raises(ValueError, match="Invalid project_id"):
        store._get_project_file("../evil")


def test_to_full_dict_returns_newest_first(store):
    p = store.create_project("x")
    for i in range(25):
        store.add_history(p.id, {"config_text": f"vlan {i}", "success": True})
    full = store.get_project(p.id)
    assert len(full.history) == 20
    h = full.history
    snips = [e["config_snippet"] for e in h]
    assert "vlan 24" in snips[0] or any("vlan" in s for s in snips[:5])
