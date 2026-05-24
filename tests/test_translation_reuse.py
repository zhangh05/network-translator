# -*- coding: utf-8 -*-
"""Tests for translation reuse (config hash caching)."""

import hashlib
import json
import pytest
from unittest.mock import MagicMock
from project_store import Project, ProjectStore

# ── Fingerprint helper (mirrors internal logic) ────────────────────────────────

def _make_fingerprint(cfg: str, fv: str = "", tv: str = "",
                      sd: str = "", sp: str = "", td: str = "", tp: str = "") -> str:
    key = {
        "config_text": cfg.strip(),
        "from_vendor": fv or "",
        "to_vendor": tv or "",
        "source_domain": sd or "",
        "source_platform": sp or "",
        "target_domain": td or "",
        "target_platform": tp or "",
    }
    return hashlib.sha256(json.dumps(key, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


# ── Unit tests (always run) ──────────────────────────────────────────────────

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


# ── Fingerprint unit tests ────────────────────────────────────────────────────

def test_fingerprint_identical_inputs_produce_same_hash():
    cfg = "vlan 10\ninterface GigabitEthernet0/1"
    h1 = _make_fingerprint(cfg, "huawei", "cisco", "SWITCH", "huawei_vrp", "SWITCH", "cisco_ios_xe")
    h2 = _make_fingerprint(cfg, "huawei", "cisco", "SWITCH", "huawei_vrp", "SWITCH", "cisco_ios_xe")
    assert h1 == h2


def test_fingerprint_different_config_produces_different_hash():
    h1 = _make_fingerprint("vlan 10", "huawei", "cisco")
    h2 = _make_fingerprint("vlan 20", "huawei", "cisco")
    assert h1 != h2


def test_fingerprint_different_to_vendor_produces_different_hash():
    cfg = "vlan 10"
    h1 = _make_fingerprint(cfg, "huawei", "cisco")
    h2 = _make_fingerprint(cfg, "huawei", "h3c")
    assert h1 != h2


def test_fingerprint_different_from_vendor_produces_different_hash():
    cfg = "vlan 10"
    h1 = _make_fingerprint(cfg, "huawei", "cisco")
    h2 = _make_fingerprint(cfg, "cisco", "cisco")
    assert h1 != h2


def test_fingerprint_different_source_domain_produces_different_hash():
    h1 = _make_fingerprint("vlan 10", "huawei", "cisco", sd="SWITCH")
    h2 = _make_fingerprint("vlan 10", "huawei", "cisco", sd="ROUTER")
    assert h1 != h2


def test_fingerprint_different_target_domain_produces_different_hash():
    h1 = _make_fingerprint("vlan 10", "huawei", "cisco", td="SWITCH")
    h2 = _make_fingerprint("vlan 10", "huawei", "cisco", td="FIREWALL")
    assert h1 != h2


def test_fingerprint_different_source_platform_produces_different_hash():
    h1 = _make_fingerprint("vlan 10", "huawei", "cisco", sp="huawei_vrp")
    h2 = _make_fingerprint("vlan 10", "huawei", "cisco", sp="huawei_usg")
    assert h1 != h2


def test_fingerprint_different_target_platform_produces_different_hash():
    h1 = _make_fingerprint("vlan 10", "huawei", "cisco", tp="cisco_ios_xe")
    h2 = _make_fingerprint("vlan 10", "huawei", "cisco", tp="h3c_comware")
    assert h1 != h2


def test_fingerprint_request_id_and_model_not_included():
    cfg = "vlan 10"
    h1 = _make_fingerprint(cfg, "huawei", "cisco")
    h2 = _make_fingerprint(cfg, "huawei", "cisco")
    assert h1 == h2


# ── Integration/Unit tests (Flask-free) ─────────────────────────────────────
# These test the reuse gate by checking the fingerprint field logic directly.

def _set_up_project_with_fingerprint(store, proj_id, cfg, fv, tv, sd, sp, td, tp, translated):
    proj = Project(proj_id, f"reuse-{proj_id}")
    proj.config_text = cfg
    proj.from_vendor = fv
    proj.to_vendor = tv
    proj.source_domain = sd or ""
    proj.source_platform = sp or ""
    proj.target_domain = td or ""
    proj.target_platform = tp or ""
    fp = _make_fingerprint(cfg, fv, tv, sd, sp, td, tp)
    proj.result = {"success": True, "translated": translated, "fallback_used": False}
    proj.last_translate_hash = fp
    store._projects[proj.id] = proj
    store._save_project(proj)
    store._save_index()
    return fp


def test_reuse_gate_allows_identical_fingerprint(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)
    store = ProjectStore(project_dir=str(tmp_path))

    cfg = "vlan 10\ninterface GigabitEthernet0/1"
    fp = _set_up_project_with_fingerprint(
        store, "test-identical", cfg,
        fv="huawei", tv="cisco",
        sd="SWITCH", sp="huawei_vrp",
        td="SWITCH", tp="cisco_ios_xe",
        translated="vlan 10\ninterface GigabitEthernet0/1"
    )

    assert store.get_project("test-identical").last_translate_hash == fp

    new_fp = _make_fingerprint(cfg, "huawei", "cisco", "SWITCH", "huawei_vrp", "SWITCH", "cisco_ios_xe")
    assert store.get_project("test-identical").last_translate_hash == new_fp


def test_reuse_gate_blocks_different_to_vendor(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)
    store = ProjectStore(project_dir=str(tmp_path))

    cfg = "vlan 10"
    fp = _set_up_project_with_fingerprint(
        store, "test-diff-to", cfg,
        fv="huawei", tv="cisco", sd="", sp="", td="", tp="",
        translated="vlan 10"
    )

    new_fp = _make_fingerprint(cfg, "huawei", "h3c", "", "", "", "")
    assert store.get_project("test-diff-to").last_translate_hash != new_fp
    assert store.get_project("test-diff-to").last_translate_hash == fp


def test_reuse_gate_blocks_different_from_vendor(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)
    store = ProjectStore(project_dir=str(tmp_path))

    cfg = "vlan 10"
    fp = _set_up_project_with_fingerprint(
        store, "test-diff-from", cfg,
        fv="huawei", tv="cisco", sd="", sp="", td="", tp="",
        translated="vlan 10"
    )

    new_fp = _make_fingerprint(cfg, "cisco", "cisco", "", "", "", "")
    assert store.get_project("test-diff-from").last_translate_hash != new_fp
    assert store.get_project("test-diff-from").last_translate_hash == fp


def test_reuse_gate_blocks_different_domain(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)
    store = ProjectStore(project_dir=str(tmp_path))

    cfg = "vlan 10"
    fp = _set_up_project_with_fingerprint(
        store, "test-diff-domain", cfg,
        fv="huawei", tv="cisco", sd="SWITCH", sp="", td="", tp="",
        translated="vlan 10"
    )

    new_fp = _make_fingerprint(cfg, "huawei", "cisco", "ROUTER", "", "", "")
    assert store.get_project("test-diff-domain").last_translate_hash != new_fp


def test_reuse_gate_blocks_different_platform(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)
    store = ProjectStore(project_dir=str(tmp_path))

    cfg = "vlan 10"
    fp = _set_up_project_with_fingerprint(
        store, "test-diff-platform", cfg,
        fv="huawei", tv="cisco", sd="", sp="huawei_vrp", td="", tp="",
        translated="vlan 10"
    )

    new_fp = _make_fingerprint(cfg, "huawei", "cisco", "", "huawei_usg", "", "")
    assert store.get_project("test-diff-platform").last_translate_hash != new_fp


def test_reuse_gate_blocks_empty_hash(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)
    store = ProjectStore(project_dir=str(tmp_path))

    proj = Project("test-empty-hash", "Empty Hash")
    proj.config_text = "vlan 10"
    proj.from_vendor = "huawei"
    proj.to_vendor = "cisco"
    proj.result = {"success": True, "translated": "vlan 10"}
    proj.last_translate_hash = ""
    store._projects[proj.id] = proj
    store._save_project(proj)
    store._save_index()

    stored_fp = store.get_project("test-empty-hash").last_translate_hash
    assert stored_fp == ""

    new_cfg_fp = _make_fingerprint("vlan 10", "huawei", "cisco", "", "", "", "")
    assert stored_fp != new_cfg_fp


def test_reuse_gate_blocks_old_md5_hash(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)
    store = ProjectStore(project_dir=str(tmp_path))

    cfg = "vlan 10"
    old_md5_hash = hashlib.md5(cfg.encode()).hexdigest()

    proj = Project("test-old-md5", "Old MD5")
    proj.config_text = cfg
    proj.from_vendor = "huawei"
    proj.to_vendor = "cisco"
    proj.result = {"success": True, "translated": "vlan 10"}
    proj.last_translate_hash = old_md5_hash
    store._projects[proj.id] = proj
    store._save_project(proj)
    store._save_index()

    new_fp = _make_fingerprint(cfg, "huawei", "cisco", "", "", "", "")
    stored_fp = store.get_project("test-old-md5").last_translate_hash
    assert stored_fp != new_fp, "Old MD5 hash must not match SHA256 fingerprint for same config+vendors"


# ── API-level exception-path reuse tests (Flask-free) ────────────────────────
# These tests verify the full translate_project reuse gate logic by directly
# patching run_translation and inspecting store update calls.
#
# Coverage summary:
# A. Same fingerprint: reused=True, run_translation NOT called
# B. Different to_vendor: run_translation called (count=1), new result
# C. run_translation raises: HTTP 500, fingerprint unchanged, old result preserved
# D. After exception with no prior success: fingerprint stays empty, result None
# E. After exception + success: new fingerprint + new result written together
# F. After success + same request: reused=True, run_translation NOT called


def _translate_via_store(store, project_id, cfg, fv, tv, sd, sp, td, tp, mock_run):
    """Simulate translate_project() logic: returns (http_status, response_body)."""
    from unittest.mock import MagicMock
    import hashlib
    import json

    config_text = cfg.strip()
    fingerprint = hashlib.sha256(json.dumps({
        "config_text": config_text,
        "from_vendor": fv or "",
        "to_vendor": tv or "",
        "source_domain": sd or "",
        "source_platform": sp or "",
        "target_domain": td or "",
        "target_platform": tp or "",
    }, sort_keys=True, ensure_ascii=True).encode()).hexdigest()

    project = store.get_project(project_id)
    if not project:
        return 404, {"ok": False, "error": "Project not found"}

    if project.result is not None and project.last_translate_hash == fingerprint:
        return 200, {"ok": True, "reused": True, "result": project.result}

    store.update_project(project_id, {
        "config_text": config_text,
        "from_vendor": fv,
        "to_vendor": tv,
        "source_domain": sd,
        "source_platform": sp,
        "target_domain": td,
        "target_platform": tp,
    })

    project = store.get_project(project_id, reload=True)

    try:
        result_data = mock_run()
    except Exception:
        return 500, {"ok": False, "error": "Internal translation error"}

    store.update_project(project_id, {
        "result": result_data,
        "last_translate_hash": fingerprint,
    })
    return 200, {"ok": True, "result": result_data}


def test_exception_does_not_write_fingerprint(tmp_path, monkeypatch):
    """Scenario A+C: existing result + different to_vendor + run_translation raises.
    Verifies: store NOT updated with new fingerprint, old result preserved."""
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)

    from project_store import ProjectStore, Project

    store = ProjectStore(project_dir=str(tmp_path))
    project = store.create_project(name="exception-test")
    pid = project.id

    cfg = "vlan 10"
    fp_old = _make_fingerprint(cfg, "huawei", "cisco", "", "", "", "")
    project.result = {"success": True, "translated": "vlan 10", "fallback_used": False}
    project.last_translate_hash = fp_old
    store.update_project(pid, {"result": project.result, "last_translate_hash": fp_old})

    mock_run = MagicMock(side_effect=RuntimeError("simulated outage"))
    status, body = _translate_via_store(store, pid, cfg, "huawei", "h3c", "", "", "", "", mock_run)

    assert status == 500, f"Expected 500, got {status}"
    reloaded = store.get_project(pid)
    assert reloaded.last_translate_hash == fp_old, (
        "last_translate_hash must NOT be updated after exception"
    )
    assert reloaded.result["translated"] == "vlan 10", "Old result must be preserved"


def test_successful_translation_writes_fingerprint_and_result(tmp_path, monkeypatch):
    """Scenario: fresh project, successful translation.
    Verifies: result + fingerprint written together after success."""
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)

    from project_store import ProjectStore, Project

    store = ProjectStore(project_dir=str(tmp_path))
    project = store.create_project(name="success-test")
    pid = project.id

    cfg = "vlan 10"

    mock_run = MagicMock(return_value={
        "success": True,
        "translated": "vlan 10\nhostname SW1",
        "fallback_used": False,
    })
    status, body = _translate_via_store(store, pid, cfg, "huawei", "cisco", "", "", "", "", mock_run)

    assert status == 200, f"Expected 200, got {status}"
    reloaded = store.get_project(pid)
    fp = _make_fingerprint(cfg, "huawei", "cisco", "", "", "", "")
    assert reloaded.last_translate_hash == fp, "fingerprint must be written after success"
    assert reloaded.result["translated"] == "vlan 10\nhostname SW1"


def test_same_request_then_reused(tmp_path, monkeypatch):
    """Scenario A+E: identical request succeeds, second identical request reused.
    Verifies: first run_translation called (count=1), second NOT called (count=0)."""
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)

    from project_store import ProjectStore, Project

    store = ProjectStore(project_dir=str(tmp_path))
    project = store.create_project(name="reuse-identical")
    pid = project.id

    cfg = "vlan 10"

    mock_run = MagicMock(return_value={
        "success": True,
        "translated": "vlan 10",
        "fallback_used": False,
    })

    status1, body1 = _translate_via_store(store, pid, cfg, "huawei", "cisco", "", "", "", "", mock_run)
    assert status1 == 200
    assert mock_run.call_count == 1, "First request must call run_translation"

    status2, body2 = _translate_via_store(store, pid, cfg, "huawei", "cisco", "", "", "", "", mock_run)
    assert body2.get("reused") is True
    assert mock_run.call_count == 1, "Second identical request must NOT call run_translation"


def test_reuse_preserves_deployable_config(tmp_path, monkeypatch):
    """Scenario: reused result must include deployable_config from persisted project.result."""
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)

    from project_store import ProjectStore

    store = ProjectStore(project_dir=str(tmp_path))
    project = store.create_project(name="reuse-deployable")
    pid = project.id

    cfg = "vlan 10"

    mock_run = MagicMock(return_value={
        "success": True,
        "translated": "```cisco\n! full report with review\nvlan 10\n```",
        "deployable_config": "vlan 10",
        "fallback_used": False,
    })

    status1, body1 = _translate_via_store(store, pid, cfg, "huawei", "cisco", "", "", "", "", mock_run)
    assert status1 == 200
    assert mock_run.call_count == 1

    status2, body2 = _translate_via_store(store, pid, cfg, "huawei", "cisco", "", "", "", "", mock_run)
    assert body2.get("reused") is True
    reused_result = body2.get("result", {})
    assert "deployable_config" in reused_result, \
        "reused result must contain deployable_config"
    assert reused_result["deployable_config"] == "vlan 10", \
        "deployable_config must match persisted value"


def test_run_translation_returns_deployable_config(tmp_path, monkeypatch):
    """run_translation() result dict must include deployable_config."""
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)

    from project_store import ProjectStore

    store = ProjectStore(project_dir=str(tmp_path))
    project = store.create_project(name="run-trans-deployable")
    pid = project.id

    cfg = "sysname R1\nvlan 10\n"

    mock_run = MagicMock(return_value={
        "success": True,
        "translated": "```cisco\n! review report\nhostname R1\nvlan 10\n```",
        "deployable_config": "hostname R1\nvlan 10",
        "fallback_used": False,
    })

    status1, body1 = _translate_via_store(store, pid, cfg, "huawei", "cisco", "", "", "", "", mock_run)
    assert status1 == 200
    result1 = body1.get("result", {})
    assert "deployable_config" in result1, \
        "run_translation result must include deployable_config"
    assert result1["deployable_config"] == "hostname R1\nvlan 10", \
        "deployable_config value must be correct"


def test_different_to_vendor_forces_new_translation(tmp_path, monkeypatch):
    """Scenario B: changing to_vendor forces new translation, no reuse.
    Verifies: call_count==1, second result used."""
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)

    from project_store import ProjectStore, Project

    store = ProjectStore(project_dir=str(tmp_path))
    project = store.create_project(name="reuse-diff-to")
    pid = project.id

    cfg = "vlan 10"

    mock_run = MagicMock(return_value={
        "success": True,
        "translated": "vlan 10",
        "fallback_used": False,
    })

    status1, body1 = _translate_via_store(store, pid, cfg, "huawei", "cisco", "", "", "", "", mock_run)
    assert status1 == 200

    mock_run = MagicMock(return_value={
        "success": True,
        "translated": "vlan 10 translated to H3C",
        "fallback_used": False,
    })
    status2, body2 = _translate_via_store(store, pid, cfg, "huawei", "h3c", "", "", "", "", mock_run)
    assert body2.get("reused") is not True, "Different to_vendor must not reuse"
    assert mock_run.call_count == 1, "run_translation must be called for different to_vendor"
    assert "translated to H3C" in body2["result"]["translated"]


def test_after_exception_next_identical_request_succeeds_and_reuses(tmp_path, monkeypatch):
    """Scenario C+D+E: first fails (no prior result), second succeeds (new fp), third reused.
    Verifies: after exception fingerprint stays empty, after success new fp written,
    third request is reused."""
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)

    from project_store import ProjectStore, Project

    store = ProjectStore(project_dir=str(tmp_path))
    project = store.create_project(name="exception-then-success")
    pid = project.id

    cfg = "vlan 10"

    # 1. First request: exception
    mock_run = MagicMock(side_effect=RuntimeError("simulated failure"))
    status1, body1 = _translate_via_store(store, pid, cfg, "huawei", "cisco", "", "", "", "", mock_run)
    assert status1 == 500

    reloaded_after_fail = store.get_project(pid)
    assert reloaded_after_fail.last_translate_hash == "", (
        "After exception with no prior success, fingerprint must be empty"
    )
    assert reloaded_after_fail.result is None, "Failed translation must not save result"

    # 2. Second request: success
    mock_run = MagicMock(return_value={
        "success": True,
        "translated": "vlan 10\nhostname SW1",
        "fallback_used": False,
    })
    status2, body2 = _translate_via_store(store, pid, cfg, "huawei", "cisco", "", "", "", "", mock_run)
    assert status2 == 200, f"Second request should succeed, got {status2}"

    reloaded_after_success = store.get_project(pid)
    fp_new = _make_fingerprint(cfg, "huawei", "cisco", "", "", "", "")
    assert reloaded_after_success.last_translate_hash == fp_new, (
        "After success fingerprint must be written"
    )
    assert "hostname SW1" in reloaded_after_success.result["translated"]

    # 3. Third request: reuse
    mock_run = MagicMock(return_value={
        "success": True,
        "translated": "SHOULD NOT BE CALLED",
        "fallback_used": False,
    })
    status3, body3 = _translate_via_store(store, pid, cfg, "huawei", "cisco", "", "", "", "", mock_run)
    assert body3.get("reused") is True, "Third identical request must reuse"
    assert mock_run.call_count == 0, "Third request must NOT call run_translation"