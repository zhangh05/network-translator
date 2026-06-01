# CI Quality Gates

> Phase 8B — 2026-05-23 | Batch J-A — 2026-05-25 (known failures resolved)

## Overview

Quality gates enforce that the validator/infrastructure core is always regression-free,
while tolerating pre-existing failures in deprecating/legacy test suites.

Two GitHub Actions jobs implement layered enforcement:

| Job | Layer | Files | Rule | Timeout |
|-----|-------|-------|------|---------|
| `core-gate` | 1 — Core | 28 files (validator, IR, domain, vendor, parser, renderer, schema contract, integration) | **Zero-tolerance** — any failure blocks | 5 min |
| `full-gate` | 2 — Extended | All remaining test files | **Regression-check** — new failures not in known pre-existing list block; pre-existing tolerated | 10 min |

## Trigger Conditions

- **Push** to `main` or `develop`
- **Pull request** targeting `main`

## GitHub Actions Runner Validation

To validate the CI workflow on a GitHub-hosted runner:

```bash
# 1. Fork the repository or push to a test branch
git checkout -b ci-validation-test
git push origin ci-validation-test

# 2. Monitor the Actions run at:
#    https://github.com/<owner>/<repo>/actions

# 3. Expected outcomes for a passing run:
#    - core-gate: PASS (0 failures in 524 core tests)
#    - full-gate: PASS (Layer 1 PASS + Layer 2: 14 tolerated failures, 0 regressions)

Both jobs run in parallel after checkout + dependency install.

## Gate Rules

### Layer 1 — Core Gate (BLOCKING)

If ANY test in the core set fails, CI fails. No exemptions.
Core files are listed in `scripts/ci_quality_gates.py` as `CORE_TEST_FILES`:

```
tests/test_domain_base.py
tests/test_domain_detector.py
tests/test_ir_base.py / test_ir_enums.py / test_ir_models.py / test_ir_prompt_version.py
tests/test_vendor_base.py / test_vendor_enums.py / test_vendor_profiles.py
tests/test_parser_base.py / test_parser_h3c_comware_switch.py / test_parser_registry.py / test_parser_shared.py
tests/test_renderer_base.py / test_renderer_cisco_ios_xe_switch.py / test_renderer_registry.py
tests/test_validator_base.py / test_validator_capability_baseline.py / test_validator_capability_gap.py
tests/test_validator_composite.py / test_validator_conversion.py / test_validator_coverage.py
tests/test_validator_residue.py / test_validator_semantic.py / test_validator_syntax.py
tests/test_schema_contract.py
tests/test_integration_phase6.py / test_integration_phase7.py
```

### Layer 2 — Full Gate (REGRESSION-CHECK)

Runs ALL `tests/test_*.py`. Failures are classified:

1. **Pre-existing** (known list below) → logged as `(known)`, tolerated, NOT blocking
2. **Regression** (not in pre-existing list) → blocks the gate, lists each new failure

Strategy: If a non-core test file currently passes, it must keep passing.
If a non-core test file is already known to fail, its failures are tracked in the pre-existing list.

### Pre-existing Failures

**All previously known failures are now resolved (Batch J-A, 2026-05-25).**

There are **0 pre-existing failures**. The CI gate has full green status.

#### Resolved
- **7 analyzer-object tests**: PyYAML installed + `/readyz` runtime checks added
- **4 Flask contract/readyz tests**: Flask installed + `/readyz` endpoint populated with `checks` dict
- **2 requests retry tests**: requests installed
- **1 packaging port test**: port calibration resolved (test now passes)

### Temporary Tolerated Items

None. All previously temporary tolerated items (packaging port calibration) have been resolved.

## How to Detect Regression Locally

```bash
# Quick check (Layer 1 only, ~0.4s)
PYTHONPATH=. python3 scripts/ci_quality_gates.py

# Full check (all layers, ~2s)
PYTHONPATH=. python3 scripts/ci_quality_gates.py --full

# With JSON report
PYTHONPATH=. python3 scripts/ci_quality_gates.py --full --json ci-report.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All gates pass |
| 1 | Layer 1 core regression (blocking) |
| 2 | Layer 2 regression (new failure outside pre-existing list) |
| 3 | Both Layer 1 and Layer 2 regressions |

### Expected Test Summary

```
Layer 1: 524 passed, 20 skipped in 0.88s  → PASS (zero-tolerance, no failures)
Layer 2: 1821 passed, 10 skipped in ~36s  → PASS (0 pre-existing, 0 regressions)
```

## Sample Run Output

```
$ PYTHONPATH=. python3 scripts/ci_quality_gates.py --full

Running Layer 1 (core) — 28 files, zero-tolerance...
  *** GATE PASS: all 28 file(s) clean ***

Running Layer 2 (extended) — 42 files, regression-tolerant...
  *** GATE PASS: no regressions, 0 pre-existing ***

JSON report written to ci-report.json
```

## Updating the Pre-existing List

When a pre-existing failure is fixed:

1. Remove the test ID from `PREEXISTING_FAILURES` in `scripts/ci_quality_gates.py`
2. Update the table in this document
3. Update the `Updated:` date in the script header comment

When a new pre-existing failure is discovered (e.g., new deprecation):

1. Add the test ID to `PREEXISTING_FAILURES` in `scripts/ci_quality_gates.py`
2. Update this document
3. Document the root cause in a ticket

## Venn Diagram: Test Coverage vs Gate Layers

```
        ┌─────────────────────────────────┐
        │      ALL tests/test_*.py (75)    │
        │  ┌───────────────────────────┐   │
        │  │ Layer 1 — Core (28 files) │   │
        │  │  Zero-tolerance, blocks   │   │
        │  └───────────────────────────┘   │
        │                                   │
        │  Layer 2 — Extended (42 files)    │
        │  Regression-check vs pre-existing │
        │                                   │
        │  Pre-existing (0) — all resolved     │
        └─────────────────────────────────┘
```

## Pre-existing Superset Tolerance Strategy

The pre-existing failure list (`PREEXISTING_FAILURES` in `scripts/ci_quality_gates.py`) is now **empty** — all previously known failures have been resolved (Batch J-A, 2026-05-25). The superset strategy is retained for future use but currently inactive.

| Environment | Deps Available | Pre-existing List Size | Expected Matches | Strategy |
|-------------|---------------|----------------------|------------------|----------|
| Local dev | all deps installed | 0 entries | 0 failures — full green | All failures are regressions |
| GitHub Actions | all deps via pip install | 0 entries | 0 failures — full green | Same behavior in both environments |

**Why this works safely:**

- The pre-existing list is empty — every test failure is a regression
- Behavior is identical across environments
- Any **new** failure is caught immediately and blocks the gate

## LLM Configuration Priority

The system supports multiple LLM configuration sources. Priority (highest to lowest):

| # | Source | Path | Override Env |
|---|--------|------|-------------|
| 1 | `LLM_SETTINGS_FILE` env var | Any path | `LLM_SETTINGS_FILE` |
| 2 | External settings file | `/Users/zhangh01/Desktop/codex_net_trans/llm_settings.txt` | — |
| 3 | Project-local `llmsetting.json` | `network-translator/llmsetting.json` | — |
| 4 | Environment variable fallbacks | — | `LLM_API_KEY`, `LLM_MODEL`, `LLM_BASE_URL`, `LLM_TIMEOUT` |

For security: API keys are **never logged in plain text** — only `***` or `(not set)` appears in any log output.

## CI vs Local Consistency

The same `scripts/ci_quality_gates.py` script is used in both environments.
All required dependencies (`flask`, `requests`, `PyYAML`) are installed locally via `requirements.txt`.
All previously known pre-existing failures are resolved.

Consistency is perfect: both environments produce identical full-green results with an empty pre-existing list.
