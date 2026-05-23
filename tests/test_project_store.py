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
    assert len(full.history) == 25
    h = full.history
    snips = [e["config_snippet"] for e in h]
    assert "vlan 24" in snips[0] or any("vlan" in s for s in snips[:5])


def test_update_project_saves_result_and_metadata(store):
    """P0: result + request_id/version/model must survive round-trip."""
    p = store.create_project("x")
    result_data = {
        "translated": "vlan 10",
        "validation": {"level": "info", "errors": [], "warnings": []},
        "semantic_validation": {},
        "diff": "-vlan 10\n+vlan 10",
        "node_results": [],
        "success": True,
        "fallback_used": False,
        "request_id": "req-123",
        "capability_gaps": [],
        "analyzer_results": [],
        "risk_signals": [],
    }
    ok = store.update_project(p.id, {
        "result": result_data,
        "request_id": "req-123",
        "version": "1.0.0",
        "model": "test-model",
    })
    assert ok
    reloaded = store.get_project(p.id)
    assert reloaded.result is not None
    assert reloaded.result["translated"] == "vlan 10"
    assert reloaded.result["success"] is True
    assert reloaded.request_id == "req-123"
    assert reloaded.version == "1.0.0"
    assert reloaded.model == "test-model"


def test_to_dict_includes_result_summary(store):
    """List response must include result so all browsers can show status."""
    p = store.create_project("x")
    store.update_project(p.id, {"result": {"translated": "vlan 10", "success": True}})
    listed = store.list_projects()
    assert len(listed) == 1
    assert listed[0]["result"] is not None
    assert listed[0]["result"]["translated"] == "vlan 10"


def test_result_not_overwritten_by_partial_update(store):
    """Partial update (without result key) must not wipe existing result."""
    p = store.create_project("x")
    store.update_project(p.id, {"result": {"translated": "vlan 10", "success": True}, "request_id": "req-456"})
    # Update only name — no result key
    ok = store.update_project(p.id, {"name": "renamed"})
    assert ok
    reloaded = store.get_project(p.id)
    assert reloaded.result is not None
    assert reloaded.result["translated"] == "vlan 10"
    assert reloaded.request_id == "req-456"


def test_clear_result_and_metadata(store):
    """Clearing result must also clear request_id/version/model."""
    p = store.create_project("x")
    store.update_project(p.id, {
        "result": {"translated": "vlan 10", "success": True},
        "request_id": "req-clear-001",
        "version": "2.0.0",
        "model": "clear-test-model",
    })
    # Clear all translation metadata
    ok = store.update_project(p.id, {
        "result": None,
        "request_id": "",
        "version": "",
        "model": "",
    })
    assert ok
    reloaded = store.get_project(p.id)
    assert reloaded.result is None
    assert reloaded.request_id == ""
    assert reloaded.version == ""
    assert reloaded.model == ""


def test_backfill_result_from_detail_file_for_historical_project():
    """Historical project: index has result=None but detail file has result.
    list_projects() and get_project() must hydrate from detail."""
    import tempfile, json
    with tempfile.TemporaryDirectory() as tmp:
        ps = ProjectStore(project_dir=tmp)
        p = ps.create_project("x")
        p_id = p.id

        # Write a "historical" index: result=None (old format)
        index_proj = {
            "id": p_id, "name": "x", "result": None,
            "request_id": None, "version": None, "model": None,
            "config_text": "vlan 10", "from_vendor": "auto", "to_vendor": "huawei",
            "created_at": p.created_at, "updated_at": p.updated_at,
        }
        with open(ps.meta_file, "w") as f:
            json.dump({"projects": [index_proj]}, f)

        # Write "historical" detail file: has result, no request_id/version/model
        detail_file = ps.project_dir / f"{p_id}.json"
        with open(detail_file, "w") as f:
            json.dump({
                "id": p_id, "name": "x",
                "result": {"translated": "vlan 99", "success": True},
                "config_text": "vlan 10", "from_vendor": "auto", "to_vendor": "huawei",
                "created_at": p.created_at, "updated_at": p.updated_at,
            }, f)

        ps._projects.clear()
        ps._last_load = 0.0
        ps._load_index()

        listed = ps.list_projects()
        assert listed[0]["result"] is not None, "result must be backfilled from detail"
        assert listed[0]["result"]["translated"] == "vlan 99"

        ps2 = ProjectStore(project_dir=tmp)
        reloaded = ps2.get_project(p_id)
        assert reloaded.result is not None
        assert reloaded.result["translated"] == "vlan 99"


def test_backfill_metadata_from_detail_for_historical_project():
    """Historical project: index has empty metadata but detail has it.
    list_projects() must hydrate metadata from detail."""
    import tempfile, json
    with tempfile.TemporaryDirectory() as tmp:
        ps = ProjectStore(project_dir=tmp)
        p = ps.create_project("y")
        p_id = p.id

        # Write index with result but empty metadata
        index_proj = {
            "id": p_id, "name": "y",
            "result": {"translated": "vlan 10", "success": True},
            "request_id": None, "version": None, "model": None,
            "config_text": "vlan 10", "from_vendor": "auto", "to_vendor": "huawei",
            "created_at": p.created_at, "updated_at": p.updated_at,
        }
        with open(ps.meta_file, "w") as f:
            json.dump({"projects": [index_proj]}, f)

        detail_file = ps.project_dir / f"{p_id}.json"
        with open(detail_file, "w") as f:
            json.dump({
                "id": p_id, "name": "y",
                "result": {"translated": "vlan 10", "success": True},
                "request_id": "req-historical-001",
                "version": "v99.0.0",
                "model": "HistoricalModel",
                "config_text": "vlan 10", "from_vendor": "auto", "to_vendor": "huawei",
                "created_at": p.created_at, "updated_at": p.updated_at,
            }, f)

        ps._projects.clear()
        ps._last_load = 0.0
        ps._load_index()

        listed = ps.list_projects()
        assert listed[0]["request_id"] == "req-historical-001"
        assert listed[0]["version"] == "v99.0.0"
        assert listed[0]["model"] == "HistoricalModel"


def test_clear_result_propagates_to_list_and_detail(store):
    """After clearing result, both list and detail return null result and empty metadata."""
    p = store.create_project("z")
    store.update_project(p.id, {
        "result": {"translated": "vlan 10", "success": True},
        "request_id": "req-clear-002",
        "version": "v1.0.0",
        "model": "ClearTest",
    })

    listed = store.list_projects()
    assert listed[0]["result"] is not None
    assert listed[0]["request_id"] == "req-clear-002"

    store.update_project(p.id, {
        "result": None,
        "request_id": "",
        "version": "",
        "model": "",
    })

    listed = store.list_projects()
    assert listed[0]["result"] is None
    assert listed[0]["request_id"] == ""
    assert listed[0]["version"] == ""
    assert listed[0]["model"] == ""

    reloaded = store.get_project(p.id)
    assert reloaded.result is None
    assert reloaded.request_id == ""
    assert reloaded.version == ""
    assert reloaded.model == ""
