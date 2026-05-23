# CI Quality Gates

> Phase 8B — 2026-05-23

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

As of 2026-05-23, these 13 tests are known to fail in this development environment.
They are tolerated by Layer 2 and do not block CI.

| # | Test | Root Cause |
|---|------|-----------|
| 1–7 | `test_analyzer_object.py::test_registry_*` (7 tests) | Deprecated FIREWALL object analyzers not registered in old pipeline registry |
| 8–9 | `test_contract_project_translate_log.py::test_project_translate_*` | Requires `flask` runtime — not installed in dev env |
| 10–11 | `test_readyz_production.py::test_readyz_reports_*` | Requires `flask` to import `web_app` |
| 12–13 | `test_v9_stability.py::test_llm_retry*` / `test_llm_max_retries*` | Requires `requests` for HTTP retry mocking |

In GitHub Actions (where `flask` and `requests` are installed), items 8–13 may pass.
The pre-existing list remains valid either way — tolerated entries that pass are simply absent from the failure set.

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
Layer 2: 13 failed, 525 passed, 3 skipped in 1.68s  → PASS (all 13 failures in pre-existing list, 0 regressions)
```

## Sample Run Output

```
$ PYTHONPATH=. python3 scripts/ci_quality_gates.py --full

Running Layer 1 (core) — 28 files, zero-tolerance...
  *** GATE PASS: all 28 file(s) clean ***

Running Layer 2 (extended) — 47 files, regression-tolerant...
  *** GATE PASS: no regressions ***
  Pre-existing (13 known, tolerated):
    (known) tests/test_analyzer_object.py::test_registry_has_address_object_analyzer
    (known) tests/test_analyzer_object.py::test_registry_has_service_object_analyzer
    (known) tests/test_analyzer_object.py::test_registry_...
    ... (13 total)

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
        │  Layer 2 — Extended (47 files)    │
        │  Regression-check vs pre-existing │
        │                                   │
        │  Pre-existing (13 tests)          │
        │  Known failures, tolerated        │
        └─────────────────────────────────┘
```

## Pre-existing Superset Tolerance Strategy

The pre-existing failure list (`PREEXISTING_FAILURES` in `scripts/ci_quality_gates.py`) is a **superset** designed to work in both local dev and CI environments without modification.

| Environment | Deps Available | Pre-existing List Size | Expected Matches | Strategy |
|-------------|---------------|----------------------|------------------|----------|
| Local dev | no flask/requests | 13 entries | 13 failures tolerated | Superset list covers all scenarios |
| GitHub Actions | flask+requests via pip install | 13 entries | ~7 failures (test_analyzer_object only) | Extra entries are harmless — absent failures simply don't match |

**Why this works safely:**

- The pre-existing list is a **union** of what fails in each environment
- `test_analyzer_object` (7 tests) fails in both — always matched
- `test_contract_project_translate_log`, `test_readyz_production`, `test_v9_stability` (6 tests) fail locally but pass in CI — simply absent from the actual failure set, never falsely flagged as regression
- Any **new** failure is caught identically in both environments because it won't be in the list anywhere

**Result**: One script, one pre-existing list, correct behavior in both environments. No `#if CI` branches.

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
The only difference is available dependencies:
- **Local dev**: may lack `flask`, `requests` → pre-existing list includes 13 entries
- **GitHub Actions**: `pip install -r requirements.txt` runs first, so `flask` and `requests` are available → pre-existing list effectively contains 7 entries (the `test_analyzer_object` ones only)

This is consistent because:
- The pre-existing list is a superset of what either environment produces
- Any entry in the list that doesn't actually fail is simply absent from the `actual_failures` set → no false positive
- Any **new** failure not in the list is correctly caught as a regression in both environments
