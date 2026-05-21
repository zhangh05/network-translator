# Network Translator — Production Roadmap

## Phase 7: Real Corpus Flywheel (Current)

**Goal**: corpus 15 → 100, benchmark 50 → 100+, failure backlog automation

| Step | Status | Description |
|------|--------|-------------|
| 46—47 | ✅ Done | Corpus baseline (15 entries), live batch (5/15 pass) |
| 48 | ✅ Done | P0 deployability fix (high-risk → dep=false) |
| 49A | ✅ Done | Annotation calibration (rtr-vrf, sw-mstp, sw-stack) |
| 49B | ✅ Done | Prompt/knowledge remediation (ASA NAT, OSPF+BFD, IRF) |
| 50 | ✅ Done | rtr-ospf-bfd-001 fix (bfd all-interfaces is valid Cisco IOS) |
| 51 | ✅ Doing | Full 15-case live rerun → backlog → P0 fixes |
| 52 | ⬜ | Corpus batch 2: add 10–20 new cases |
| 53 | ⬜ | Live failure remediation batch P1 |
| 54 | ⬜ | Corpus growth discipline memo |
| 55 | ⬜ | Live quality target tracking |

**Acceptance**: live report + backlog + P0/P1 fix records + all gates green

---

## Phase 8: Collaboration & Iteration Automation (In Progress)

**Goal**: one-command status, one-command iteration, automatic backlog

| Product | Status | Description |
|---------|--------|-------------|
| TASK_HANDOFF.md | ✅ Done | Session handoff document |
| reports/ | ✅ Done | `live_failure_backlog.md`, `live_summary.json`, `latest_status.md` |
| scripts/project_status.sh | ✅ Done | Single-command project health |
| scripts/run_iteration.sh | ✅ Done | Quick/full iteration check |
| tools/live_failure_backlog.py | ✅ Done | Live report → backlog MD + JSON |
| ITERATION_WORKFLOW.md | ✅ Done | Remediation loop documentation |
| Git branch workflow | ⬜ | Standard branch/review/merge flow |
| Sync scripts (PS1) | ⬜ | Remote server sync automation |

**Acceptance**: one command to see status, one to run iteration, live failures → backlog

---

## Phase 9: Production Deployment Standardization

**Goal**: operation-ready service

| Product | Priority | Description |
|---------|----------|-------------|
| systemd service file | P1 | Managed process lifecycle |
| Dockerfile / docker-compose | P1 | Containerized deployment |
| nginx reverse proxy example | P1 | TLS termination + rate limiting |
| logrotate config | P2 | Log rotation policy |
| backup/restore scripts | P2 | Data backup strategy |
| .env-based config | P1 | Environment variable management |
| auth/rate-limiting | P1 | API security baseline |

**Acceptance**: restartable, recoverable, logs rotate, config safe, auth clear

---

## Phase 10: Productization

**Goal**: end-to-end user workflow

| Product | Priority | Description |
|---------|----------|-------------|
| Batch config translation | P1 | Multiple config upload/translate |
| Project version diff | P2 | Compare translations across versions |
| Human review workbench | P1 | UI for reviewing/managing translations |
| Risk filtering | P2 | Filter by risk/capability/feature |
| Export migration report | P2 | Structured migration documents |
| User corrections → corpus | P2 | Feedback loop to grow corpus |
| Knowledge suggestion | P3 | AI-suggested knowledge file updates |

**Acceptance**: user completes translate → review → export → feedback loop

---

## Technical Optimization Roadmap

| Area | Priority | Description |
|------|----------|-------------|
| Prompt compaction | P1 | Shrink growing knowledge context to control token usage |
| Feature chunking | P2 | Split large configs by feature (interface/nat/policy/routing) |
| Fine-grained scoring | P2 | feature_score, risk_score, deployability_score |
| Multi-model evaluation | P2 | Same corpus, different LLMs, compare quality/cost/latency |
| Human feedback loop | P2 | User corrections → corpus candidates → knowledge patches |
| Knowledge conflict detection | P3 | Detect conflicting knowledge files for same feature |
| Analyzer coverage report | P3 | Stats on which cases hit which analyzers |

---

## Priority Rules

**P0**: unsafe_success, high-risk deployable=true, API 500, secret leak, full config in logs  
**P1**: live corpus failure, key command residue, wrong platform syntax, missing MANUAL_REVIEW, timeout  
**P2**: coverage, UX, docs, performance

## Quality Gates (every iteration)

- `pytest` (targeted first, full when feasible)
- `python tools/validate_corpus.py`
- `python tools/corpus_to_bench.py` (if annotations changed)
- `python bench/run_cases.py --corpus-only --static-only`
- `python scripts/release_gate.py` (larger changes)
- healthz/readyz check (if services touched)
- No secret leakage in docs/logs
