# Release Manifest — v11 Phase 7 Production Ready

**Tag:** `v11-phase7-production-ready`
**Commit:** `d31d266`
**Date:** 2026-05-21
**Status:** ✅ PRODUCTION

---

## Quality Summary

| Gate | Result |
|------|--------|
| Release gate (8/8) | ✅ ALL PASS |
| Pytest | ✅ 486/486 passed (499 collected) |
| Static bench (corpus) | ✅ 15/15 |
| Static bench (total) | ✅ 50/50 |
| Live corpus | ⚠️ 14/15 (93%) |
| Timeout alignment | ✅ GUNICORN_TIMEOUT=240 ≥ LLM_TIMEOUT=180+30=210 |

---

## Live Corpus Result

**14/15 pass — fw-nat-001 is a known LLM non-determinism issue**

| Case | Status | Note |
|------|--------|------|
| fw-nat-001 | ⚠️ INTERMITTENT | NAT LLM output non-deterministic; validator correctly blocks deployability on MANUAL_REVIEW |
| All others (14 cases) | ✅ PASS | |

**Mitigation:** Validator blocks deployability when `MANUAL_REVIEW` appears in LLM output. No false deployable observed.

---

## Known Limitation

**fw-nat-001 — NAT Translation Non-Determinism**

- NAT scenarios may intermittently produce LLM outputs requiring manual review
- Root cause: LLM output varies between calls for same input (non-deterministic sampling)
- Safety mechanism: `validator` detects `MANUAL_REVIEW` markers → blocks `deployable`
- Observed: 1 intermittent failure out of ~3 runs; 93% pass rate
- Accepted as known limitation; not a blocker for production

---

## Deliverables

### Reports

| File | Description |
|------|-------------|
| `reports/RELEASE_v11_PHASE7.md` | Phase 7 release summary |
| `reports/RC3_REPORT.md` | RC3 intermediate report |
| `reports/coverage_matrix.md` | Feature/analyzer coverage |
| `reports/live_failure_backlog.md` | Live failure analysis |
| `reports/live_summary.json` | Live run JSON summary |
| `reports/targeted_rerun.json` | Flaky case rerun results |

### Documentation

| File | Description |
|------|-------------|
| `docs/CORPUS_GUIDE.md` | Corpus annotation and validation guide |
| `docs/ITERATION_WORKFLOW.md` | Iteration workflow (Annotate → Validate → Generate) |
| `docs/ROADMAP.md` | Project roadmap |
| `docs/OPERATIONS.md` | Operations runbook |
| `docs/RELEASE_CHECKLIST.md` | Release checklist |
| `README.md` | Project overview (Graph+IR architecture) |
| `MAINTENANCE.md` | Known limitations |

### Source

- **Tag:** `v11-phase7-production-ready` → `d31d266`
- **Architecture:** DAG of 9 nodes (ParseNode → KnowledgeNode → TranslateNode → SemanticValidatorNode → RouteNode → ValidateNode → DiffNode → FallbackNode → MemoryNode)
- **IR:** LLM-driven Intermediate Representation (parse_to_ir / translate_ir / compare_ir)
- **Fallback:** RuleBasedTranslator for high-frequency commands (ACL/VLAN/静态路由)

---

## Deployment Commands

```bash
# Restart with latest code (git pull if updated)
./scripts/stop.sh && ./scripts/start.sh

# Verify running
./scripts/service.sh status
curl -s http://localhost:5008/healthz   # expect: OK
curl -s http://localhost:5008/readyz     # expect: ready
curl -s http://localhost:5008/api/version

# Run release gate (full)
python3 scripts/release_gate.py --mode release

# Run static bench only
python3 bench/run_cases.py --static-only --corpus-only
```

---

## Rollback Command

```bash
# Immediate rollback to v11-phase7-production-ready
git checkout v11-phase7-production-ready
./scripts/stop.sh && ./scripts/start.sh
```

---

## Server Current Status (2026-05-21)

```
pid:      866970
port:     5008
host:     0.0.0.0
healthz:  OK
readyz:   ready
version:  v=v11-phase7-step53-dev analyzers=15 features=45
```
