# Phase 8 Plan — Stability & Production Operations

**Base:** `v11-phase7-production-ready` (commit `8eb24b7`)
**Goal:** Eliminate live flakiness, improve production observability, and harden operational runbooks — no new translation features.
**Constraint:** No changes to core translation logic (IR, graph nodes, analyzers, rule translator).

---

## 1. Phase 8 Objectives

1. **Live stability** — reduce or eliminate `fw-nat-001` / `fw-nat-server-001` / `fw-ipsec-vpn-001` intermittent failures
2. **Worker isolation** — slow LLM requests must not exhaust the gunicorn worker pool
3. **Production ops automation** — self-healing restart, log rotation, alerting hooks
4. **Frontend review workflow** — structured manual review UX for flagged translations (P2)

---

## 2. Not in Scope

- No new translation features (IR improvements, new analyzers, new vendors)
- No corpus expansion
- No LLM model changes
- No database adoption (SQLite WAL, PostgreSQL)
- No SemanticMemory embedding upgrade
- No multi-turn / agent memory improvements

---

## 3. Priority Roadmap

### P0 — Live Stability: fw-nat-001 / fw-nat-server-001 / fw-ipsec-vpn-001

**Objective:** Understand root cause of intermittent NAT/IPsec failures; reduce flakiness rate.

**Root cause hypothesis (from MAINTENANCE.md):**
- LLM output non-determinism on platform-specific NAT/IPsec semantics
- Validator correctly catches MANUAL_REVIEW markers, but cases still fail intermittently
-fw-nat-server-001 and fw-ipsec-vpn-001 have ~30% pass rate

**Scope of changes:**
- `knowledge_data/{huawei,cisco}/nat.md`, `knowledge_data/{huawei,cisco}/ipsec.md` — prompt hardening (more explicit alternatives, fewer ambiguous options)
- `core/graph/nodes.py` TranslateNode system prompt tweaks only — no logic changes
- No new validators, no analyzer changes

**Risk:** Low — only prompt/knowledge changes, rollback is trivial (git revert)

**Acceptance criteria:**
- [ ] `fw-nat-001` pass rate ≥ 90% (from ~85%)
- [ ] `fw-nat-server-001` pass rate ≥ 60% (from ~30%)
- [ ] `fw-ipsec-vpn-001` pass rate ≥ 60% (from ~30%)
- [ ] All existing 14/15 cases remain at 100% (no regression)
- [ ] `MANUAL_REVIEW` is still correctly produced when appropriate (validator still working)

---

### P1 — Async Job Queue / Worker Isolation

**Objective:** LLM requests (up to 180s) must not block gunicorn workers. Slow requests should be handled by a separate async queue.

**Scope of changes:**
- `core/llm_queue.py` (new) — in-process queue with threading; requests submitted, polling for results
- `web_app.py` — `/api/translate` and `/api/projects/<id>/translate` submit job, return `job_id` immediately
- `/api/jobs/<job_id>` (new) — poll for job completion
- `scripts/service.sh` — add `WORKER_POOL_SIZE` env var to separate slow-worker pool (optional P1b)
- No gevent/uvicorn dependency changes; stay on gunicorn

**Risk:** Medium — introduces async state tracking; need to handle job TTL, orphaned jobs, worker crash recovery

**Acceptance criteria:**
- [ ] `/api/translate` returns `{job_id: "..."}` within 500ms for LLM requests
- [ ] `/api/jobs/<id>` returns completed result when ready
- [ ] `/api/jobs/<id>` returns `{"status": "running"}` while LLM is in progress
- [ ] Slow LLM (180s) does NOT block any gunicorn worker
- [ ] Job results expire from memory after 1 hour
- [ ] `/api/translate` still works synchronously for rule-based translations (no job_id)

---

### P1 — Production Ops Automation

**Objective:** Self-healing restarts, log rotation, health monitoring, and alerting hooks for production runs.

**Scope of changes:**
- `scripts/service.sh` — add `restart-on-health-fail` daemon mode; add log rotation (`logrotate` config); add `health-check` subcommand
- `scripts/health_check.sh` (new) — curl healthz/readyz, check disk/memory, alert on failure
- `logs/translator.log` — rotate when > 100MB
- `scripts/release_gate.py` — add `--check-live` to gate (optional)
- No new dependencies (use existing `curl`, `logrotate`, `systemd` timer if available)

**Risk:** Low — operational script only, no core logic

**Acceptance criteria:**
- [ ] `./scripts/service.sh health-check` exits 0 when healthy, exits 2 when degraded
- [ ] `./scripts/service.sh start` creates logrotate config
- [ ] Service self-restarts within 30s after healthz goes red (if daemon mode enabled)
- [ ] Release gate `--check-live` runs a 3-case smoke test against live API

---

### P2 — Frontend Review Workflow

**Objective:** Structured UI for `manual_review_required=true` translations — users can review, approve/reject, and re-translate.

**Scope of changes:**
- `templates/index.html` (or `static/`) — add review panel for flagged translations
- `web_app.py` — add `/api/jobs/<job_id>` (if P1 async done), add `/api/reviews` endpoints
- `project_store.py` — add `review_status` field to translation result (pending/approved/rejected)
- `logs/translation.jsonl` — add `review_*` fields
- No changes to graph nodes or translation logic

**Risk:** Medium — adds stateful review workflow; need to handle review audit trail

**Acceptance criteria:**
- [ ] UI shows "Manual Review Required" badge for `manual_review_required=true` translations
- [ ] User can approve (sets `review_status=approved`) or reject (`review_status=rejected`) with optional note
- [ ] Rejected translation can be re-submitted for re-translation
- [ ] Review action is logged in JSONL
- [ ] `/api/projects/<id>` returns `review_status` in project result

---

## 4. Recommended Execution Order

```
Phase 8a: P0 — Live Stability
  1. Analyze last 10 fw-nat-001 / fw-nat-server-001 / fw-ipsec-vpn-001 failures
  2. Hardening prompts + knowledge docs
  3. Re-run targeted_rerun.py 3× to confirm improvement
  4. Merge to master

Phase 8b: P1 — Async Job Queue (after P0 merged)
  5. Design job state tracking (in-memory + optional Redis/DB later)
  6. Implement job queue + /api/jobs endpoints
  7. Update web_app translate endpoints to use async path
  8. Smoke test with LLM-enabled translation

Phase 8c: P1 — Production Ops Automation (after P0 merged)
  9. health_check.sh + service.sh daemon mode
  10. logrotate config
  11. release_gate --check-live

Phase 8d: P2 — Frontend Review Workflow (after P1 async)
  12. Review state in project_store
  13. /api/reviews endpoints
  14. UI review panel
```

---

## 5. Phase 8 Exit Criteria

All must pass before Phase 8 is considered complete:

| Criterion | Target |
|-----------|--------|
| Live corpus | ≥ 15/15 (P0 resolved all flaky cases) |
| Release gate | 8/8 PASS |
| Pytest | 486/486 passed (no new regressions) |
| fw-nat-001 pass rate | ≥ 90% |
| fw-nat-server-001 pass rate | ≥ 60% |
| fw-ipsec-vpn-001 pass rate | ≥ 60% |
| Async job queue | Working; slow LLM does not block workers |
| Ops automation | health_check passes; self-heal confirmed |
| Frontend review | Manual review workflow functional end-to-end |
| No code regression | Static bench 50/50; no new `deployable: true` on broken output |

---

## 6. Open Questions

1. **Job queue persistence** — in-memory (lost on restart) vs JSONL checkpoint (slower)? Recommend in-memory for P1, add optional Redis later.
2. **fw-nat-server-001** still at 30% — if P0 prompt hardening doesn't improve, is the case annotation wrong (`deployable: false, mr: true` already correct)?
3. **Worker pool separation** — should slow LLM requests use a dedicated 1-worker pool separate from the 4-worker fast-path pool? Or shared queue with polling?
4. **Alerting** — email/webhook on health check failure? Or just log+restart (PagerDuty integration out of scope)?

---

## 7. Phase 8 Commit Convention

Each deliverable should be its own commit with a `phase8/` prefix:

```
phase8/p0: harden nat/ipsec prompts + knowledge
phase8/p1-async: add job queue + /api/jobs
phase8/p1-ops: health check + self-heal + logrotate
phase8/p2-review: review workflow frontend + /api/reviews
```
