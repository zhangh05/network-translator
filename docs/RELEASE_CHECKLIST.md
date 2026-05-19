# Release Checklist

## Pre-Release Verification

Run these steps in order:

### 1. Test Suite

```bash
cd /root/network-translator
PYTHONPATH=. ./venv/bin/pytest tests/ -v
```

**Pass criteria**: All tests pass, no unexpected failures.

### 2. Knowledge Lint

```bash
PYTHONPATH=. python3 tools/knowledge_lint.py --coverage
```

**Pass criteria**: P0 coverage = 100%. Non-blocking warnings allowed.

### 3. Coverage Inventory

```bash
PYTHONPATH=. python3 tools/coverage_inventory.py
```

**Pass criteria**: Generates `docs/coverage/coverage_matrix.json` without errors.

### 4. Static Benchmarks

```bash
PYTHONPATH=. python3 bench/run_cases.py --static
```

**Pass criteria**: 35/35 cases pass (smoke=12, core=14, full=9).

### 5. Release Gate

```bash
PYTHONPATH=. python3 scripts/release_gate.py
```

**Pass criteria**: Output contains `RELEASE_GATE_OK` and `avg_score` ≥ 90.

### 6. Health Check

```bash
./scripts/status.sh
curl --noproxy '*' http://localhost:5008/healthz
```

**Pass criteria**: Service running, `/healthz` returns `{"ok":true,"status":"healthy"}`.

### 7. Readiness Check

```bash
curl --noproxy '*' http://localhost:5008/readyz
```

**Pass criteria**: `{"ok":true,"status":"ready"}`. `LLM_API_KEY` warnings are acceptable.

### 8. Version Endpoint

```bash
curl --noproxy '*' http://localhost:5008/api/version
```

**Pass criteria**: Returns `version`, `analyzers` (13+), `features` (44+), `model`, `python`.

### 9. E2E Smoke Test

```bash
# Create a project
curl --noproxy '*' -s -X POST http://localhost:5008/api/projects \
  -H "Content-Type: application/json" \
  -d '{"name":"smoke"}' | python3 -c "import sys,json; print(json.load(sys.stdin).get('project',{}).get('id','FAIL'))"
```

**Pass criteria**: Returns a project ID.

### 10. API Key Leak Check

```bash
grep -rn "sk-" logs/ 2>/dev/null || echo "No secrets in logs"
grep -rn "LLM_API_KEY" logs/ 2>/dev/null || echo "No API key env in logs"
```

**Pass criteria**: No API key strings in log output.

### 11. VERSION Confirmation

```bash
cat VERSION
```

**Pass criteria**: VERSION reflects the intended release label.

## Release Gate Summary

| Step | Command | Pass Criteria |
|------|---------|---------------|
| 1 | `pytest` | All pass |
| 2 | `knowledge_lint --coverage` | P0 = 100% |
| 3 | `coverage_inventory.py` | No errors |
| 4 | `bench/run_cases.py --static` | 35/35 |
| 5 | `release_gate.py` | RELEASE_GATE_OK, score ≥ 90 |
| 6 | `/healthz` | 200 OK |
| 7 | `/readyz` | status = ready |
| 8 | `/api/version` | valid response |
| 9 | E2E smoke | Project created |
| 10 | Secret leak | No API keys in logs |
| 11 | `cat VERSION` | Correct label |

## Rolling Back

If a release introduces issues:

1. Stop the service: `./scripts/stop.sh`
2. Revert to previous version: `git checkout <previous-tag>`
3. Restart: `./scripts/start.sh`
4. Verify: `./scripts/status.sh`
