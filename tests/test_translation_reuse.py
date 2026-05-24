# -*- coding: utf-8 -*-
"""Tests for translation reuse (config hash caching)."""

import hashlib
import json
import pytest
from project_store import Project, ProjectStore

# Flask is only available in the system Python (not venv). API-level tests
# that require Flask test_client are marked with @pytest.mark.flask.
# venv users: run full test suite with system Python instead.
try:
    from web_app import create_app  # noqa: F401
    _HAS_FLASK = True
except ImportError:
    _HAS_FLASK = False

flask_required = pytest.mark.skipif(not _HAS_FLASK, reason="Flask not available in venv (use system Python for API tests)")


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


# ── Exception-path reuse tests ──────────────────────────────────────────────────
# These tests use Flask test_client via web_app to cover the full API route.

@flask_required
def test_exception_does_not_write_fingerprint(tmp_path, monkeypatch):
    """run_translation failure must not write new fingerprint over old result."""
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)

    from web_app import create_app
    app = create_app()
    client = app.test_client()

    from project_store import get_project_store
    store = get_project_store()
    pid = store.create_project(name="exception-test")["id"]

    cfg = "vlan 10"
    fp_old = _make_fingerprint(cfg, "huawei", "cisco", "", "", "", "")
    proj = store.get_project(pid)
    proj.result = {"success": True, "translated": "vlan 10", "fallback_used": False}
    proj.last_translate_hash = fp_old
    store.update_project(pid, {"result": proj.result, "last_translate_hash": fp_old})

    from unittest.mock import patch
    with patch("project_store.run_translation") as mock_run:
        mock_run.side_effect = RuntimeError("simulated provider outage")
        resp = client.post(f"/api/projects/{pid}/translate", json={
            "config_text": cfg,
            "from_vendor": "huawei",
            "to_vendor": "h3c",
        })

    assert resp.status_code == 500, f"Expected 500, got {resp.status_code}"

    reloaded = store.get_project(pid)
    assert reloaded.last_translate_hash == fp_old, (
        "last_translate_hash must NOT be updated to new fingerprint after failure"
    )
    assert reloaded.result["translated"] == "vlan 10", "Old result must be preserved"


@flask_required
def test_successful_translation_writes_fingerprint_and_result(tmp_path, monkeypatch):
    """run_translation success must atomically write result + new fingerprint."""
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)

    from web_app import create_app
    app = create_app()
    client = app.test_client()

    from project_store import get_project_store
    store = get_project_store()
    pid = store.create_project(name="success-test")["id"]

    cfg = "vlan 10"

    from unittest.mock import patch
    with patch("project_store.run_translation") as mock_run:
        mock_run.return_value = {"success": True, "translated": "vlan 10\nhostname SW1", "fallback_used": False}
        resp = client.post(f"/api/projects/{pid}/translate", json={
            "config_text": cfg,
            "from_vendor": "huawei",
            "to_vendor": "cisco",
        })

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    body = resp.get_json()
    assert body.get("ok") is True

    reloaded = store.get_project(pid)
    fp = _make_fingerprint(cfg, "huawei", "cisco", "", "", "", "")
    assert reloaded.last_translate_hash == fp, "fingerprint must be written after success"
    assert reloaded.result["translated"] == "vlan 10\nhostname SW1"


@flask_required
def test_same_request_then_reused(tmp_path, monkeypatch):
    """Second identical request returns reused=True without calling run_translation."""
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)

    from web_app import create_app
    app = create_app()
    client = app.test_client()

    from project_store import get_project_store
    store = get_project_store()
    pid = store.create_project(name="reuse-identical")["id"]

    cfg = "vlan 10"

    from unittest.mock import patch
    with patch("project_store.run_translation") as mock_run:
        mock_run.return_value = {"success": True, "translated": "vlan 10", "fallback_used": False}
        resp1 = client.post(f"/api/projects/{pid}/translate", json={
            "config_text": cfg,
            "from_vendor": "huawei",
            "to_vendor": "cisco",
        })
        assert resp1.status_code == 200

        mock_run.return_value = {"success": True, "translated": "SHOULD NOT BE CALLED", "fallback_used": False}
        resp2 = client.post(f"/api/projects/{pid}/translate", json={
            "config_text": cfg,
            "from_vendor": "huawei",
            "to_vendor": "cisco",
        })
        body2 = resp2.get_json()
        assert body2.get("reused") is True
        assert mock_run.call_count == 0, "run_translation must not be called on reuse"


@flask_required
def test_different_to_vendor_forces_new_translation(tmp_path, monkeypatch):
    """Changing to_vendor must not reuse old result."""
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)

    from web_app import create_app
    app = create_app()
    client = app.test_client()

    from project_store import get_project_store
    store = get_project_store()
    pid = store.create_project(name="reuse-diff-to")["id"]

    cfg = "vlan 10"

    from unittest.mock import patch
    with patch("project_store.run_translation") as mock_run:
        mock_run.return_value = {"success": True, "translated": "vlan 10", "fallback_used": False}
        resp1 = client.post(f"/api/projects/{pid}/translate", json={
            "config_text": cfg,
            "from_vendor": "huawei",
            "to_vendor": "cisco",
        })
        assert resp1.status_code == 200

        mock_run.return_value = {"success": True, "translated": "vlan 10 translated to H3C", "fallback_used": False}
        resp2 = client.post(f"/api/projects/{pid}/translate", json={
            "config_text": cfg,
            "from_vendor": "huawei",
            "to_vendor": "h3c",
        })
        body2 = resp2.get_json()
        assert body2.get("reused") is not True, "Different to_vendor must not reuse"
        assert mock_run.call_count == 1, "run_translation must be called for different to_vendor"
        assert "translated to H3C" in body2["result"]["translated"]


@flask_required
def test_after_exception_next_identical_request_succeeds_and_reuses(tmp_path, monkeypatch):
    """After a failed request, the next identical request must succeed and then reuse."""
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent))
    monkeypatch.setattr("project_store.PROJECT_DIR", tmp_path)

    from web_app import create_app
    app = create_app()
    client = app.test_client()

    from project_store import get_project_store
    store = get_project_store()
    pid = store.create_project(name="exception-then-success")["id"]

    cfg = "vlan 10"

    from unittest.mock import patch
    with patch("project_store.run_translation") as mock_run:
        mock_run.side_effect = RuntimeError("simulated failure")
        resp1 = client.post(f"/api/projects/{pid}/translate", json={
            "config_text": cfg,
            "from_vendor": "huawei",
            "to_vendor": "cisco",
        })
        assert resp1.status_code == 500

        reloaded_after_fail = store.get_project(pid)
        fp_old = _make_fingerprint(cfg, "huawei", "cisco", "", "", "", "")
        assert reloaded_after_fail.last_translate_hash == fp_old, (
            "After exception fingerprint must still be old (empty before first success)"
        )
        assert reloaded_after_fail.result is None, "Failed translation must not save result"

        mock_run.side_effect = None
        mock_run.return_value = {"success": True, "translated": "vlan 10\nhostname SW1", "fallback_used": False}
        resp2 = client.post(f"/api/projects/{pid}/translate", json={
            "config_text": cfg,
            "from_vendor": "huawei",
            "to_vendor": "cisco",
        })
        assert resp2.status_code == 200, f"Second request should succeed, got {resp2.status_code}"

        reloaded_after_success = store.get_project(pid)
        fp_new = _make_fingerprint(cfg, "huawei", "cisco", "", "", "", "")
        assert reloaded_after_success.last_translate_hash == fp_new, "After success fingerprint must be written"
        assert "hostname SW1" in reloaded_after_success.result["translated"]

        mock_run.return_value = {"success": True, "translated": "SHOULD NOT BE CALLED", "fallback_used": False}
        mock_run.side_effect = None
        resp3 = client.post(f"/api/projects/{pid}/translate", json={
            "config_text": cfg,
            "from_vendor": "huawei",
            "to_vendor": "cisco",
        })
        body3 = resp3.get_json()
        assert body3.get("reused") is True, "Third identical request must reuse"