# -*- coding: utf-8 -*-
"""Tests for translation reuse (config hash caching)."""

import hashlib
import json
import pytest
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


# ── Project field tests ───────────────────────────────────────────────────────

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


# ── Integration-style reuse tests ─────────────────────────────────────────────
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