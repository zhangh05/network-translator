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

**Objective:** Characterize and reduce live flakiness with a disciplined metric framework. Accept that some NAT/IPsec cases are inherently hard for LLMs; the goal is honest measurement and risk-appropriate handling.

---

#### P0 Metric Definitions

| Metric | Definition |
|--------|------------|
| **live correctness pass rate** | Single run: 15/15 clean pass. Or: 3 consecutive runs average ≥ 14/15 |
| **clean deployable rate** | Output is `deployable: true` AND `manual_review_required: false` AND `validator_fatal_count: 0` |
| **manual_review accepted pass** | Output is `deployable: false` OR `manual_review_required: true` AND the reason is legitimate (validator correctly identified a hard case) |
| **false deployable count** | Output is `deployable: true` but the translated config has platform residue, semantic errors, or missing critical config. Target: **0** |
| **repeated-run stability** | Same case run 3× — all 3 produce consistent deployability decision |

**P0 does NOT pursue:**
- Forcing all hard NAT/IPsec cases to be `deployable: true`
- Closing the validator to make scores look better
- Marking uncertain LLM output as `deployable: true`
- Using annotation overrides to hide real quality problems (annotation may only document expected `manual_review_required=true` cases)

---

#### P0 Targeted Rerun Targets

| Case | Correctness | Clean Deployable | manual_review accepted | HTTP 500/timeout |
|------|-------------|-----------------|------------------------|-----------------|
| `fw-nat-001` | ≥ 90% (3/3) | ≥ 70% | documented as acceptable | 0 |
| `fw-nat-server-001` | ≥ 80% | ≥ 60% **or** `mr: true` documented | must be legitimate reason | 0 |
| `fw-ipsec-vpn-001` | ≥ 80% | ≥ 60% **or** `mr: true` documented | must be legitimate reason | 0 |
| All other 12 corpus cases | **15/15** single run | 100% | always clean | 0 |

**Correctness** means the output is semantically equivalent to source (or correctly flagged as uncertain). **Clean deployable** means it passes all validators with no manual review required.

If `fw-nat-server-001` and `fw-ipsec-vpn-001` cannot reach clean deployable targets, the annotation must be updated to document `manual_review_required: true` as the expected outcome, not treated as a failure.

---

#### P0 Scope of Changes

- `knowledge_data/{huawei,cisco}/nat.md`, `knowledge_data/{huawei,cisco}/ipsec.md` — prompt hardening (more explicit alternatives, fewer ambiguous options)
- `core/graph/nodes.py` TranslateNode system prompt tweaks only — no logic changes
- No new validators, no analyzer changes
- `corpus/annotations/` — update annotation for any case whose expected outcome changes (e.g., `fw-nat-server-001 mr: true` formally documented)

**Risk:** Low — only prompt/knowledge changes, rollback is trivial (git revert)

**P0 Acceptance criteria:**
- [ ] `fw-nat-001` targeted rerun 3×: ≥ 90% correctness, ≥ 70% clean deployable, 0 HTTP 500/timeout
- [ ] `fw-nat-server-001` targeted rerun 3×: ≥ 80% correctness, ≥ 60% clean deployable OR `manual_review_required: true` formally annotated and accepted
- [ ] `fw-ipsec-vpn-001` targeted rerun 3×: ≥ 80% correctness, ≥ 60% clean deployable OR `manual_review_required: true` formally annotated and accepted
- [ ] All other 12 corpus cases: 15/15 in a single run (no regression)
- [ ] False deployable count across all targeted runs: **0**
- [ ] `manual_review` is still correctly produced when appropriate (validator unchanged)
- [ ] MAINTENANCE.md updated with Phase 8 findings

---

### P1 — Async Job Queue / Worker Isolation

**Objective:** LLM requests (up to 180s) must not block gunicorn workers. Slow requests handled by an async queue with polling.

**Minimum implementation scope:**

```
core/llm_queue.py (new):
  - JobState: queued / running / succeeded / failed / expired
  - in-memory dict: job_id → {state, request_id, submitted_at, result, error}
  - submit(request_id, llm_fn) → job_id
  - get(job_id) → {state, result|error, submitted_at}
  - TTL: jobs expire from memory after 3600s (1 hour)

web_app.py:
  - POST /api/translate  → if LLM needed: submit() → return {job_id} immediately
  - GET /api/jobs/<job_id> → poll for result {state, result|error, deployability, risk_signals}
  - Rule-based translations: still synchronous (no job_id)
  - Timeout/error: propagate LLM timeout as {state: failed, error: "llm_timeout"}

JSONL / log linkage:
  - Each job logs translation_event with job_id
  - JSONL entry written on job completion (succeeded/failed)
  - Frontend can poll /api/jobs/<id> and display result

Frontend (API-ready only, no full UI):
  - /api/jobs/<job_id> returns {job_id, state, result, error} — frontend polls
  - Frontend full UX deferred to P2
```

**What is NOT in P1 async scope:**
- No Redis or external queue dependency
- No websocket / Server-Sent Events
- No separate slow-worker gunicorn pool (defer to P1b)
- No job result persistence to disk (in-memory only; lost on restart)

**Risk:** Medium — introduces async state; job orphaned on worker restart is acceptable (client retries)

**P1 async acceptance criteria:**
- [ ] `/api/translate` returns `{job_id: "..."}` within 500ms for LLM requests
- [ ] `/api/jobs/<id>` returns `{state: "queued"` → `"running"` → `"succeeded"` or `"failed"`}`
- [ ] Slow LLM (180s) does NOT block any gunicorn worker
- [ ] LLM timeout propagates as `{state: "failed", error: "llm_timeout"}`
- [ ] Rule-based translation still synchronous (no job_id in response)
- [ ] Each completed job has a corresponding JSONL entry with job_id
- [ ] Job results expire from memory after 1 hour

---

### P1 — Production Ops Automation

**Objective:** Self-healing restarts, health monitoring, log rotation, and a daily smoke test for production runs.

**Scope of changes:**

```
scripts/health_check.sh (new):
  - curl /healthz → exit 0 if OK, exit 2 if fail
  - curl /readyz → exit 0 if ready, exit 2 if not ready
  - check disk space (logs/ not > 90% full)
  - check memory (worker not OOM)
  - LLM connectivity test: OPTIONAL (skip if no LLM_API_KEY set)
  - Exit codes: 0=healthy, 1=unknown, 2=degraded

scripts/service.sh additions:
  - `health-check` subcommand (calls health_check.sh)
  - `restart-on-health-fail` mode: if health-check fails 3× in a row,
    stop service and restart (daemon mode)
  - logrotate config written to /etc/logrotate.d/translator on start

logrotate:
  - logs/translator.log       {size > 100MB, rotate 5, compress}
  - logs/access.log           {size > 100MB, rotate 5, compress}
  - logs/error.log            {size > 50MB,  rotate 3, compress}
  - logs/translation.jsonl    {size > 500MB, rotate 10, compress}
  - translation.jsonl is NOT deleted by logrotate — only rotated

scripts/daily_smoke.sh (new):
  - Run: bench/run_cases.py smoke tier against live API
  - Exit 0 if all pass, exit 1 if any fail
  - Intended for: cron job `0 6 * * *` (daily morning smoke)

scripts/release_gate.py:
  - `--check-live` flag: runs 3-case smoke test against live API
  - Non-blocking warning if live smoke fails (does not block release gate)
```

**What is NOT in P1 ops scope:**
- PagerDuty / email / webhook alerting integrations
- Deletion of translation.jsonl logs (rotation only)
- systemd unit file generation
- Kubernetes/health-check-probe integration

**Risk:** Low — operational scripts only, no core logic

**P1 ops acceptance criteria:**
- [ ] `./scripts/health_check.sh` exits 0 when service healthy, exits 2 when degraded
- [ ] `./scripts/service.sh start` writes logrotate config to `/etc/logrotate.d/translator`
- [ ] `restart-on-health-fail` mode: service restarts within 30s after 3 consecutive health failures
- [ ] `logs/translation.jsonl` is rotated but never deleted by logrotate
- [ ] `./scripts/daily_smoke.sh` smoke tier passes against live service
- [ ] `scripts/release_gate.py --check-live` runs 3-case smoke and warns on failure (non-blocking)

---

### P2 — Frontend Review Workflow

**Objective:** Structured manual review for `manual_review_required=true` translations — reviewer approves/rejects, with full audit trail. **Does not change backend deployability判断.**

**Core principle:** The graph's `deployability` and `manual_review_required` flags are immutable outputs of the translation pipeline. The review workflow records the reviewer's decision but does not override or flip those flags.

---

#### Review Data Model

```
review_id:          UUID
job_id:             links to translation job (from P1 async)
translation_id:     stable ID of the translation result
reviewer:           "human" | "automated"
reviewed_at:        ISO timestamp
decision:           approved | rejected | escalated

Original translation output (read-only in review):
  - risk_signals:       grouped {platform_residue, semantic_warnings, ...}
  - manual_review_lines: list of line-level MANUAL_REVIEW annotations
  - deployability:       true | false  (from backend, not mutable)
  - validator_fatal_count, validator_warning_count

Reviewer action:
  - decision: approved   → translator accepts output as-is for deployment
  - decision: rejected   → translator must not be deployed; record reason
  - decision: escalated  → unresolved; flag for engineering

review_note:        optional free text from reviewer
review_report:      generated summary of all reviews in date range (export)
```

---

#### API Endpoints

```
GET  /api/reviews                    → list reviews (paginated)
GET  /api/reviews/<review_id>        → get single review
POST /api/reviews                    → create review {job_id, decision, note}
GET  /api/reviews/report?from=&to=   → export review report as JSON

POST /api/projects/<id>/translate
  → if result.manual_review_required: flag for review panel
  → frontend shows "Manual Review Required" badge
```

**Note:** If P1 async is not complete, job_id is optional in POST /api/reviews; review can be created from project translate result directly.

---

#### What is NOT in P2 scope:
- Changing backend `deployability` or `manual_review_required` based on review decision
- Automatic approval/rejection rules
- Integration with deployment pipelines (approval does not auto-deploy)
- Reviewer authentication / authorization (defer to future auth work)

---

**P2 acceptance criteria:**
- [ ] UI shows "Manual Review Required" badge when `manual_review_required=true`
- [ ] Reviewer can `approve` / `reject` / `escalate` with optional note
- [ ] Review decision is persisted and returned in `GET /api/reviews/<id>`
- [ ] Reviewer can export a date-range review report (`GET /api/reviews/report`)
- [ ] Review action is written to JSONL with `review_*` fields
- [ ] Backend `deployability` is **never** overwritten by review decision
- [ ] `/api/projects/<id>` includes `review_status` in project result (pending/approved/rejected/null)
- [ ] Rejected translation can be re-submitted (new translation job, not auto-retry)

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
| Release gate | 8/8 PASS |
| Pytest | 486/486 passed (no new regressions) |
| Static bench | 50/50 (no regression) |
| **Live correctness** | 15/15 single run, OR 3-run average ≥ 14/15 |
| **False deployable count** | **0** across all Phase 8 runs |
| **fw-nat-001** | ≥ 90% correctness, ≥ 70% clean deployable, 0 infra errors |
| **fw-nat-server-001** | ≥ 80% correctness, ≥ 60% clean deployable OR `mr: true` annotated+accepted |
| **fw-ipsec-vpn-001** | ≥ 80% correctness, ≥ 60% clean deployable OR `mr: true` annotated+accepted |
| **Async job queue smoke** | `/api/translate` returns job_id; `/api/jobs/<id>` returns correct state transitions; LLM does not block worker |
| **Ops health check** | `health_check.sh` exits 0; `daily_smoke.sh` smoke tier passes; logrotate active |
| **Review workflow** | approve/reject/escalate functional; review audit trail in JSONL; export report works |
| **MAINTENANCE.md** | Updated with Phase 8 findings, accepted limitations, and any annotation changes |

**Phase 8 is done when all 11 criteria are met.**

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
