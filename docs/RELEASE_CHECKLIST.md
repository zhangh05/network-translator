# Release Checklist

> Phase 8D — 2026-05-25 (Batch I-J: Beta acceptance documented)

## Pre-Release Verification

Run these steps in order.

### 0. Beta Acceptance Doc Consistency

```bash
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_beta_acceptance_docs.py -v
```

**Pass criteria**: All tests pass. JSON and Markdown numbers match.

See `docs/BETA_ACCEPTANCE_2026-05-25.md` and `docs/beta_acceptance_2026_05_25.json`.

### 1. CI Quality Gates (core + regression)

```bash
PYTHONPATH=. python3 scripts/ci_quality_gates.py --full --json /tmp/ci-report.json
```

**Pass criteria**: Exit code 0 (`ALL GATES PASS`). Layer 1 zero failures. Layer 2 zero regressions (known pre-existing tolerated).

### 2. Validator Tests

```bash
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_validator*.py tests/test_schema_contract.py -v --tb=short
```

**Pass criteria**: All pass.

### 3. Integration Chains (Phase 6 + Phase 7)

```bash
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_integration_phase6.py tests/test_integration_phase7.py -v --tb=short
```

**Pass criteria**: All pass (18 + 21 = 39 tests).

### 4. Audit Traceability Drill

```bash
PYTHONPATH=. bash scripts/audit_trace.sh
```

**Pass criteria**: Exit code 0. `docs/audit/trace_*.json` contains both chains with `result: "PASS"`.

### 5. Performance Baseline (Phase 8A)

```bash
PYTHONPATH=. python3 scripts/run_baseline.py
```

**Pass criteria**: 0 errors. Baseline written to `docs/phase8_perf_baseline.json`.

### 6. Full Test Suite

```bash
PYTHONPATH=. venv/bin/python3 -m pytest tests/ -v
```

**Pass criteria**: 1069+ passed, 13 pre-existing failures tolerated, 0 unexpected regressions.

### 7. Knowledge Lint

```bash
PYTHONPATH=. python3 tools/knowledge_lint.py --coverage
```

**Pass criteria**: P0 coverage = 100%.

### 8. Health Check

```bash
./scripts/start.sh
curl --noproxy '*' http://localhost:5008/healthz
```

**Pass criteria**: Service running, `/healthz` returns `{"ok":true,"status":"healthy"}`.

### 9. Readiness Check

```bash
curl --noproxy '*' http://localhost:5008/readyz
```

**Pass criteria**: `{"ok":true,"status":"ready"}`.

### 10. Version Endpoint

```bash
curl --noproxy '*' http://localhost:5008/api/version
```

**Pass criteria**: Returns version, analyzers, features, model, python.

### 11. E2E Smoke Test

```bash
curl --noproxy '*' -s -X POST http://localhost:5008/api/projects \
  -H "Content-Type: application/json" \
  -d '{"name":"smoke"}' | python3 -c "import sys,json; print(json.load(sys.stdin).get('project',{}).get('id','FAIL'))"
```

**Pass criteria**: Returns a project ID.

### 12. API Key Leak Check

```bash
grep -rn "sk-" logs/ 2>/dev/null || echo "No secrets in logs"
grep -rn "LLM_API_KEY" logs/ 2>/dev/null || echo "No API key env in logs"
```

**Pass criteria**: No API key strings in logs.

### 13. VERSION Confirmation

```bash
cat VERSION
```

**Pass criteria**: VERSION reflects the intended release label.

## Release Gate Summary

| Step | Command | Pass Criteria |
|------|---------|---------------|
| 0 | `pytest test_beta_acceptance_docs` | All pass, JSON+MD consistent |
| 1 | `ci_quality_gates.py --full` | Exit 0, no regressions |
| 2 | `pytest test_validator* test_schema_contract` | All pass |
| 3 | `pytest test_integration_phase6 + phase7` | 39/39 pass |
| 4 | `audit_trace.sh` | Exit 0, both chains PASS |
| 5 | `run_baseline.py` | 0 errors |
| 6 | `pytest tests/` | 1778+ pass, 0 regressions |
| 7 | `knowledge_lint --coverage` | P0 = 100% |
| 8 | `/healthz` | 200 OK |
| 9 | `/readyz` | status = ready |
| 10 | `/api/version` | valid response |
| 11 | E2E smoke | Project created |
| 12 | Secret leak | No API keys in logs |
| 13 | `cat VERSION` | Correct label |

## Rolling Back

If a release introduces issues:

1. Stop the service: `./scripts/stop.sh`
2. Revert to previous version: `git checkout <previous-tag>`
3. Restart: `./scripts/start.sh`
4. Verify: `./scripts/status.sh`
5. Run CI quality gates: `PYTHONPATH=. python3 scripts/ci_quality_gates.py --full`
