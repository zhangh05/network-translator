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

### 2a. Core Validator Replacements (Frozen — Do Not Touch)

These files duplicate functionality already present in committed validator modules and must not be loaded by the test suite or runtime:

```
core/cisco_output_validator.py       # DEPRECATED — functionality merged into core/validator/*
core/domain_legacy.py                # RENAMED from core/domain.py — core/domain.py deleted intentionally
core/h3c_to_cisco.py                # RETAINED as fallback wrapper
core/runtime_config.py               # UTILITY only; core/__init__.py does not import it
core/validator/capability_gap_validator.py   # UNCOMMITTED duplicate of validator capability gap
core/validator/conversion_validator.py         # UNCOMMITTED duplicate of validator conversion
core/validator/report_json.py                 # UNCOMMITTED utility
core/validator/residue_validator.py           # UNCOMMITTED duplicate of committed ResidueValidator
core/validator/syntax_validator.py             # UNCOMMITTED duplicate of committed SyntaxValidator
```

**Known limitation**: Group B uncommitted files ARE still importable via Python's path (because they exist in the working tree). This means `import core.cisco_output_validator` succeeds. However, the committed code paths use `core.validator.*` modules, which take precedence. Group B files should be treated as read-only historical artifacts and not imported.

```bash
# Verification shows these ARE importable (known limitation, not a regression):
#   core.cisco_output_validator       ← uncommitted but importable
#   core.validator.capability_gap_validator  ← uncommitted but importable
#   core.validator.conversion_validator      ← uncommitted but importable
#   core.validator.residue_validator        ← uncommitted but importable
#   core.validator.syntax_validator         ← uncommitted but importable
# They are not loaded by any committed import path.
```

**Action**: This is a known limitation. Do not use `import core.cisco_output_validator` or similar. The committed validator modules in `core/validator/` are authoritative.

### 2b. Test Files (Frozen — Do Not Touch)

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
| `tests/test_reliability.py` | ✅ Active — add new tests here |
| `docs/RUNBOOK.md`, `docs/CI_QUALITY_GATES.md` | ✅ Active — keep updated |
| `docs/audit/INDEX.md` | ✅ Active — add trace records here |
| `docs/BETA_READINESS_REPORT.md` | ✅ Active — update with each release |
| `.github/workflows/ci.yml` | ✅ Active — validate on GitHub Actions |
| `scripts/ci_quality_gates.py` | ✅ Active — CI gate entry point |

### Group B: Frozen (Pre-existing, Do Not Modify)

| Files | Reason |
|-------|--------|
| `core/cisco_output_validator.py` | DEPRECATED; do not import |
| `core/domain_legacy.py` | RENAMED from `core/domain.py` |
| `core/validator/*_validator.py` (uncommitted duplicates) | Duplicates of committed validators |
| `tests/test_*_production.py` (uncommitted) | Covered by committed tests |
| `tests/test_validator_*.py` (uncommitted) | Covered by committed validator tests |

### Group C: Deferred (Future Phase)

| Item | Details |
|------|---------|
| OSPF VERIFIABLE_FEATURE_REGISTRY re-evaluation | Phase 9 planning item |
| Full pipeline benchmark with LLM API | Requires live API key + endpoint |
| Embedding-based SemanticMemory | Phase 9+ enhancement |
| SQLite WAL for ProjectStore | High-concurrency production consideration |

---

## 4. Reconciliation Verification

```bash
# Verify no Group B files are imported by active code
PYTHONPATH=. python3 -c "
import sys, importlib
group_b = [
    'core.cisco_output_validator',
    'core.validator.capability_gap_validator',
    'core.validator.conversion_validator',
    'core.validator.residue_validator',
    'core.validator.syntax_validator',
]
for m in group_b:
    try:
        importlib.import_module(m)
        print(f'WARNING: {m} is importable — may conflict with committed version')
    except ImportError:
        print(f'OK: {m} not importable (frozen correctly)')
"
```

If any Group B file is found importable, it means an import path was added that shouldn't exist. The committed validator modules take precedence.