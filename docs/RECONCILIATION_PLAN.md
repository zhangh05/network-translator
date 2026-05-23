# Reconciliation Plan

> Beta Production Trial — 2026-05-23

## Purpose

This document distinguishes **changes made during the Beta optimization round** from **pre-existing uncommitted code that predates this work**. It enables clean handover and clear ownership of each artifact.

---

## 1. Changes Made During Beta Round

All changes in this section are committed (commits `0205591` through `6814416`).

| Commit | Scope | Files |
|--------|--------|-------|
| `0205591` | LLM config convergence + security + Beta report | `llm_settings.py`, `tests/test_llm_settings_external.py`, `docs/RUNBOOK.md`, `docs/CI_QUALITY_GATES.md`, `docs/BETA_READINESS_REPORT.md` |
| `04a8209` | LLM reliability tests (retry classification, URL norm, fallback) | `tests/test_reliability.py` |
| `4c916f8` | CI gates doc — GitHub runner validation steps | `docs/CI_QUALITY_GATES.md` |
| `6814416` | Audit archive — trace-to-code paths + schema verification | `docs/audit/INDEX.md` |

**Status**: All files are committed. These are frozen per Beta scope.

---

## 2. Pre-existing Uncommitted Code (Historical)

The following files exist in the working tree but have **never been committed** to any branch.
They predate the Beta round and are **NOT part of this scope**.

### 2a. Validator Replacements (Committed in Reconciliation Round 1)

These files were previously uncommitted but are now tracked because active code imports them:

```
core/domain_legacy.py                # ✅ COMMITTED — imported by core/domain/__init__.py, web_app, coverage_inventory
core/runtime_config.py               # ✅ COMMITTED — imported by web_app, llm_settings
core/validator/capability_gap_validator.py   # ✅ COMMITTED — imported by core/validator/__init__.py
core/validator/conversion_validator.py       # ✅ COMMITTED — imported by core/validator/__init__.py
core/validator/report_json.py                 # ✅ COMMITTED — imported by core/validator/__init__.py
core/validator/residue_validator.py          # ✅ COMMITTED — imported by core/validator/__init__.py, batch/__init__.py
core/validator/syntax_validator.py          # ✅ COMMITTED — imported by core/validator/__init__.py
```

### 2b. Deprecated/Deleted Files

```
core/domain.py                       # ✅ DELETED — replaced by core/domain_legacy.py + core/domain/package
core/cisco_output_validator.py      # ❌ FROZEN — deprecated, not imported by active code
core/h3c_to_cisco.py                 # ❌ FROZEN — fallback wrapper, only imported by test_h3c_to_cisco.py and cisco_output_validator.py
```

### 2c. Test Files (Frozen — Do Not Touch)

```
tests/test_h3c_to_cisco.py          # UNCOMMITTED — functionality covered by committed tests
tests/test_llm_settings_production.py   # UNCOMMITTED — already tested via test_llm_settings_production.py in staged files? (file exists, not yet committed)
tests/test_packaging_production.py  # UNCOMMITTED — already covered
tests/test_readyz_production.py    # UNCOMMITTED — already covered
tests/test_runtime_config.py       # UNCOMMITTED utility tests
tests/test_validator_capability_gap.py  # UNCOMMITTED
tests/test_validator_conversion.py      # UNCOMMITTED
tests/test_validator_residue.py        # UNCOMMITTED
tests/test_validator_syntax.py         # UNCOMMITTED
```

### 2c. Documentation Files (Frozen — Do Not Touch)

```
docs/PHASE5B_ACCEPTANCE.md           # UNCOMMITTED but exists at docs/PHASE5B_ACCEPTANCE.md
docs/superpowers/plans/2026-05-22-multi-vendor-ir-platform.md  # UNCOMMITTED design doc
```

---

## 3. Grouping: Manage / Freeze / Defer

### Group A: Managed (Active Scope)

| Files | Action |
|-------|--------|
| `llm_settings.py` | ✅ Active — continue using |
| `tests/test_llm_settings_external.py` | ✅ Active — add new tests here |
| `tests/test_llm_settings_production.py` | ✅ Active — add new tests here |
| `tests/test_reliability.py` | ✅ Active — add new tests here |
| `docs/RUNBOOK.md`, `docs/CI_QUALITY_GATES.md` | ✅ Active — keep updated |
| `docs/audit/INDEX.md` | ✅ Active — add trace records here |
| `docs/BETA_READINESS_REPORT.md` | ✅ Active — update with each release |
| `.github/workflows/ci.yml` | ✅ Active — validate on GitHub Actions |
| `scripts/ci_quality_gates.py` | ✅ Active — CI gate entry point |
| `core/domain_legacy.py`, `core/runtime_config.py` | ✅ Active — imported by active code |
| `core/validator/capability_gap_validator.py` etc. | ✅ Active — imported by active code |

### Group B: Frozen (Pre-existing, Do Not Modify)

| Files | Reason |
|-------|--------|
| `core/cisco_output_validator.py` | DEPRECATED; not imported by active code |
| `core/h3c_to_cisco.py` | Fallback wrapper; only test imports |
| `tests/test_h3c_to_cisco.py` | Frozen; functionality covered elsewhere |
| `tests/test_packaging_production.py` | Frozen; covered by test_packaging_production.py in staged |
| `tests/test_readyz_production.py` | Frozen; covered by test_readyz_production.py |
| `tests/test_runtime_config.py` | Frozen; runtime_config committed |
| `tests/test_validator_*.py` | Frozen; validators committed |

### Group C: Deferred (Future Phase)

| Item | Details |
|------|---------|
| OSPF VERIFIABLE_FEATURE_REGISTRY re-evaluation | Phase 9 planning item |
| Full pipeline benchmark with LLM API | Requires live API key + endpoint |
| Embedding-based SemanticMemory | Phase 9+ enhancement |
| SQLite WAL for ProjectStore | High-concurrency production consideration |

---

## 4. Reconciliation Verification (Round 1 Complete)

After Round 1, the following are confirmed committed:
- `core/domain_legacy.py` ✅
- `core/runtime_config.py` ✅
- `core/validator/capability_gap_validator.py` ✅
- `core/validator/conversion_validator.py` ✅
- `core/validator/report_json.py` ✅
- `core/validator/residue_validator.py` ✅
- `core/validator/syntax_validator.py` ✅
- `core/domain.py` DELETED ✅

The following remain frozen (not imported by active code):
- `core/cisco_output_validator.py`
- `core/h3c_to_cisco.py`
- `tests/test_h3c_to_cisco.py`
- `tests/test_validator_*.py` (uncommitted versions)

If any Group B file is found importable, it means an import path was added that shouldn't exist. The committed validator modules take precedence.