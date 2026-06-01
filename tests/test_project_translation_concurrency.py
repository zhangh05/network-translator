# -*- coding: utf-8 -*-
"""Concurrency guards for project translation requests."""

import threading
import time

from project_store import ProjectStore, TranslationSlotLimiter, project_translation_lock


def test_project_exposes_translation_status_fields():
    p = ProjectStore._project_from_data("p1", {
        "name": "demo",
        "translation_status": "translating",
        "active_request_id": "req-1",
        "active_translate_hash": "hash-1",
        "translation_started_at": "2026-06-01T00:00:00Z",
    })
    d = p.to_dict()
    assert d["translation_status"] == "translating"
    assert d["active_request_id"] == "req-1"
    assert d["active_translate_hash"] == "hash-1"
    assert d["translation_started_at"] == "2026-06-01T00:00:00Z"


def test_project_store_updates_and_clears_translation_status(tmp_path):
    store = ProjectStore(project_dir=str(tmp_path))
    p = store.create_project("lock-status")

    assert store.update_project(p.id, {
        "translation_status": "translating",
        "active_request_id": "req-2",
        "active_translate_hash": "hash-2",
        "translation_started_at": "2026-06-01T01:00:00Z",
    })
    active = store.get_project(p.id, reload=True)
    assert active.translation_status == "translating"
    assert active.active_request_id == "req-2"

    assert store.update_project(p.id, {
        "translation_status": "idle",
        "active_request_id": "",
        "active_translate_hash": "",
        "translation_started_at": "",
    })
    cleared = store.get_project(p.id, reload=True)
    assert cleared.translation_status == "idle"
    assert cleared.active_request_id == ""
    assert cleared.active_translate_hash == ""


def test_project_translation_lock_serializes_same_project(tmp_path):
    acquired = []
    release_first = threading.Event()

    def contender():
        with project_translation_lock(tmp_path, "same-project"):
            acquired.append("second")

    with project_translation_lock(tmp_path, "same-project"):
        t = threading.Thread(target=contender)
        t.start()
        time.sleep(0.1)
        assert acquired == [], "second same-project translation must wait for first lock"
        release_first.set()
    t.join(timeout=2)
    assert acquired == ["second"]


def test_translation_slot_limiter_caps_concurrent_slots(tmp_path):
    limiter = TranslationSlotLimiter(run_dir=tmp_path, limit=1, wait_interval=0.02)
    acquired = []

    def contender():
        with limiter.acquire("req-2", "p2"):
            acquired.append("second")

    with limiter.acquire("req-1", "p1"):
        t = threading.Thread(target=contender)
        t.start()
        time.sleep(0.1)
        assert acquired == [], "second global LLM slot must wait while limit is full"
    t.join(timeout=2)
    assert acquired == ["second"]


def test_identical_concurrent_project_translate_waits_and_reuses(tmp_path, monkeypatch):
    import project_store as ps
    from web_app import create_app

    store = ProjectStore(project_dir=str(tmp_path))
    project = store.create_project("concurrent")
    monkeypatch.setattr(ps, "_project_store", store)

    calls = []
    first_started = threading.Event()
    allow_finish = threading.Event()

    def fake_run_translation(**kwargs):
        calls.append(kwargs)
        first_started.set()
        assert allow_finish.wait(timeout=2), "test timed out waiting to finish first translation"
        return {
            "success": True,
            "translated": "hostname SW1",
            "deployable_config": "hostname SW1",
            "fallback_used": False,
        }

    monkeypatch.setattr(ps, "run_translation", fake_run_translation)
    app = create_app()
    payload = {"config_text": "sysname SW1", "from_vendor": "huawei", "to_vendor": "cisco"}
    responses = []

    def post_translate():
        with app.test_client() as client:
            responses.append(client.post(f"/api/projects/{project.id}/translate", json=payload).get_json())

    t1 = threading.Thread(target=post_translate)
    t1.start()
    assert first_started.wait(timeout=2), "first translation did not start"

    t2 = threading.Thread(target=post_translate)
    t2.start()
    time.sleep(0.1)
    assert len(calls) == 1, "second identical request should wait, not start another translation"

    # Other browsers should be able to see the project is currently translating.
    active = store.get_project(project.id, reload=True)
    assert active.translation_status == "translating"
    assert active.active_translate_hash

    allow_finish.set()
    t1.join(timeout=2)
    t2.join(timeout=2)

    assert len(calls) == 1, "identical concurrent request must reuse the first completed result"
    assert sorted(r.get("reused", False) for r in responses) == [False, True]
    final = store.get_project(project.id, reload=True)
    assert final.translation_status == "idle"
    assert final.active_request_id == ""
