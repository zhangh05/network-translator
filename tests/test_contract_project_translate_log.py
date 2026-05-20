import json
import os
import tempfile
import pytest


def _set_temp_log(web_app):
    tmpdir = tempfile.mkdtemp()
    log_dir = type(web_app.LOG_DIR)(tmpdir)
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "translation.jsonl"
    return tmpdir, log_dir, log_file


def _restore_log(web_app, orig_dir, orig_file, tmpdir):
    web_app.LOG_DIR = orig_dir
    web_app.TRANSLATION_LOG = orig_file
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_project_translate_writes_jsonl():
    """P0-3: translate_project() must write to translation JSONL log."""
    import web_app as wa
    orig_dir = wa.LOG_DIR
    orig_file = wa.TRANSLATION_LOG
    tmpdir, log_dir, log_file = _set_temp_log(wa)
    wa.LOG_DIR = log_dir
    wa.TRANSLATION_LOG = log_file

    try:
        from web_app import create_app
        app = create_app()
        client = app.test_client()

        from project_store import get_project_store
        store = get_project_store()
        project = store.create_project(name="Test Logging")
        pid = project.id

        resp = client.post(f"/api/projects/{pid}/translate", json={
            "config_text": "hostname R1\ninterface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n no shutdown\n",
            "from_vendor": "cisco",
            "to_vendor": "huawei",
        })
        assert resp.status_code == 200
        body = resp.get_json()
        assert body.get("ok") is True

        assert log_file.exists(), f"JSONL log not created at {log_file}"

        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) >= 1, "Expected at least 1 log entry"

        last_entry = json.loads(lines[-1])
        assert last_entry["request_id"] == body["request_id"]
        assert "success" in last_entry
        assert "elapsed_ms" in last_entry
        assert "config_snippet" in last_entry
    finally:
        _restore_log(wa, orig_dir, orig_file, tmpdir)


def test_project_translate_jsonl_contains_analyzer_results():
    """P0-3: JSONL entry from project translate must include analyzer_results."""
    import web_app as wa
    orig_dir = wa.LOG_DIR
    orig_file = wa.TRANSLATION_LOG
    tmpdir, log_dir, log_file = _set_temp_log(wa)
    wa.LOG_DIR = log_dir
    wa.TRANSLATION_LOG = log_file

    try:
        from web_app import create_app
        app = create_app()
        client = app.test_client()

        from project_store import get_project_store
        store = get_project_store()
        project = store.create_project(name="Test Analyzer Log")
        pid = project.id

        resp = client.post(f"/api/projects/{pid}/translate", json={
            "config_text": "hostname R1\ninterface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n no shutdown\n",
            "from_vendor": "cisco",
            "to_vendor": "huawei",
        })
        assert resp.status_code == 200

        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        last_entry = json.loads(lines[-1])
        assert "analyzer_results" in last_entry
        assert "analyzer_warning_count" in last_entry
        assert "analyzer_fatal_count" in last_entry
    finally:
        _restore_log(wa, orig_dir, orig_file, tmpdir)
