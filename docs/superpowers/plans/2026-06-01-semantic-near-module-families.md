# Semantic-Near Module Families Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand module-level semantic-near suggestions beyond QoS so high-frequency route, switching, gateway, and management modules show reviewer-friendly target skeletons without entering deployable config.

**Architecture:** Keep `deployable_config` strict. Extend `core/module_graph/translator.py` so selected manual-review modules can return `status="semantic_near"` with `suggested_lines`; `manual_review_lines` remains evidence and risk signals still require confirmation. Do not change parser/renderer/validator contracts.

**Tech Stack:** Python 3.9, pytest, existing `core/module_graph` models and `RuleBasedTranslator` helpers.

---

### Task 1: Add semantic-near regression tests

**Files:**
- Modify: `tests/test_module_graph.py`

- [ ] Add tests proving route-policy, BGP policy, FHRP, DHCP relay, and management modules produce `semantic_near` results with `suggested_lines` while staying out of `deployable_config`.
- [ ] Run: `PYTHONPATH=. venv/bin/python3 -m pytest tests/test_module_graph.py::<new-tests> -q`
- [ ] Expected: tests fail because only QoS currently supports `semantic_near`.

### Task 2: Implement route/control-plane semantic-near suggestions

**Files:**
- Modify: `core/module_graph/translator.py`

- [ ] Extend `_semantic_near_result()` dispatch for `route_policy`, `bgp.policy`, `fhrp.*`, `dhcp.relay`, `dhcp.relay.binding`, `management.ntp`, `management.snmp`, and `management.logging`.
- [ ] Add small helper functions that parse only low-risk skeletons; secrets must be redacted and risky lines must remain comments/suggestions only.
- [ ] Run targeted tests until green.

### Task 3: Document module-family boundary

**Files:**
- Modify: `docs/CONFIG_MODULE_GRAPH.md`

- [ ] Add a short table of semantic-near families and explicitly state these suggestions are not deployable output.
- [ ] Run docs-adjacent tests if any fail in gate.

### Task 4: Verify and commit

**Files:**
- All modified files.

- [ ] Run targeted module/risk/frontend tests.
- [ ] Run fallback suite sanity tests.
- [ ] Run `git diff --check`.
- [ ] Run `PYTHONPATH=. python3 scripts/ci_quality_gates.py --full`.
- [ ] Commit with `feat(modules): broaden semantic-near module families`.
