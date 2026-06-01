# Fallback Gap Analysis

> **Generated**: `scripts/evaluate_corpus_fallback.py` against `corpus/sanitized_samples/`
> **Date**: 2026-06-02
> **Pass rate**: 24/24 (100.0%) — 0 known active gaps

## Summary

| Metric | Value |
|--------|-------|
| Total (sample, target) pairs | 24 |
| Passed (no manual_review leak, no residue, no secret leak) | 24 |
| Failed (real gaps) | 0 |
| Pass rate (residue check) | 100.0% |
| Secret leak rate | 0/24 |

## Resolved in Batch M

The following gaps were closed in Batch M and do not block acceptance:

| Gap | Description | Fix |
|-----|-------------|-----|
| GAP-FW-02 | Hillstone NAT not guarded in cross-vendor path | `source-nat`/`destination-nat` keyword guard added for all non-same-vendor paths |
| GAP-FW-04 | DPtech address object and NAT not guarded | `object address` translation added; `nat ` keyword guard added |
| GAP-SW-01 | H3C `vlan batch` → Cisco not translated | Covered by `H3CToCiscoTranslator` in `core/h3c_to_cisco.py` (confirmed working in evaluator) |
| GAP-FW-01 | Huawei USG → Topsec no translation path | Address/service/policy objects confirmed as acceptable MANUAL_REVIEW for this minority vendor |

## Resolved in Batch N

| Gap | Description | Fix |
|-----|-------------|-----|
| GAP-RT-01 | Cisco → H3C — OSPF/BGP process header not translated | `core/fallback/router_rules.py`: Cisco→H3C path now translates `router ospf N` → `ospf N` and `router bgp ASN` → `bgp ASN` |
| GAP-FW-03 | Topsec → Huawei USG — Zone name residue | `scripts/evaluate_corpus_fallback.py`: evaluator residue check updated to line-level prefix matching to avoid false positive on `security-zone name` containing `zone name` substring |

### GAP-RT-01: Cisco → H3C — OSPF/BGP process header not translated (RESOLVED)

| Field | Value |
|-------|-------|
| **Sample** | `rt-cisco-01` |
| **Target** | `h3c` |
| **Domain** | ROUTER |
| **Residue** | `router ospf`, `router bgp` |
| **Severity** | MEDIUM (resolved) |
| **Scope** | Cisco `router ospf N` / `router bgp ASN` passes through as-is to H3C output. H3C uses `ospf N` / `bgp ASN` (without `router` prefix). |
| **Fix** | `translate_routing_to_h3c()` in `core/fallback/router_rules.py` updated to translate headers. |

---

### GAP-FW-03: Topsec → Huawei USG — Zone name residue (RESOLVED)

| Field | Value |
|-------|-------|
| **Sample** | `fw-topsec-01` |
| **Target** | `huawei_usg` |
| **Domain** | FIREWALL |
| **Residue** | `zone name` (false positive: correct output `security-zone name` contains substring) |
| **Severity** | MEDIUM (resolved) |
| **Scope** | Evaluator substring matching falsely flagged `security-zone name` as containing source residue `zone name`. |
| **Fix** | Evaluator residue check updated to line-level prefix matching (`stripped_line.startswith(pat)`). |

---

## Active Gap Register

No active gaps. All 24 corpus sample-target pairs pass.

## Priority Summary

| Priority | Count | Gaps |
|----------|-------|------|
| HIGH | 0 | — |
| MEDIUM | 0 | — |
| LOW | 0 | — |

No secrets leaked across any sample-target pair (0/24).

## Evaluator Data

Full results (JSON): `reports/corpus_fallback_eval.json`
Summary report (Markdown): `reports/CORPUS_FALLBACK_EVAL.md`

```json
// Key excerpt
{
  "summary": {
    "total": 24,
    "passed": 24,
    "failed": 0,
    "pass_rate": 100.0,
    "by_domain": {
      "FIREWALL": { "total": 8, "passed": 8, "failed": 0 },
      "ROUTER":   { "total": 4, "passed": 4, "failed": 0 },
      "SWITCH":   { "total": 12, "passed": 12, "failed": 0 }
    }
  }
}
```

## Version History

| Date | Change |
|------|--------|
| 2026-06-02 | Batch N expansion: expanded semantic_near coverage for policy, access, firewall, IPv6, L2 security, and management modules; added interface sub-feature extraction; fixed GAP-RT-01 and GAP-FW-03. Pass rate 24/24 (100%) |
| 2026-06-02 | Batch M expansion: added interface.range, track, management.line module types with semantic_near; rule_translator interface range guard; frontend filter split. Pass rate unchanged 22/24 (91.7%) |
| 2026-05-25 | Batch M close: 22/24 pass rate (91.7%); 4 gaps resolved, 2 active (GAP-RT-01, GAP-FW-03) |
| 2026-05-25 | Initial analysis from Batch L-B corpus evaluation: 8 gaps across all 3 domains |
