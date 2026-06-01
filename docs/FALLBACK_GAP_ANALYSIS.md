# Fallback Gap Analysis

> **Generated**: `scripts/evaluate_corpus_fallback.py` against `corpus/sanitized_samples/`
> **Date**: 2026-06-02
> **Pass rate**: 22/24 (91.7%) — 2 known active gaps

## Summary

| Metric | Value |
|--------|-------|
| Total (sample, target) pairs | 24 |
| Passed (no manual_review leak, no residue, no secret leak) | 22 |
| Failed (real gaps) | 2 |
| Pass rate (residue check) | 91.7% |
| Secret leak rate | 0/24 |

## Resolved in Batch M

The following gaps were closed in Batch M and do not block acceptance:

| Gap | Description | Fix |
|-----|-------------|-----|
| GAP-FW-02 | Hillstone NAT not guarded in cross-vendor path | `source-nat`/`destination-nat` keyword guard added for all non-same-vendor paths |
| GAP-FW-04 | DPtech address object and NAT not guarded | `object address` translation added; `nat ` keyword guard added |
| GAP-SW-01 | H3C `vlan batch` → Cisco not translated | Covered by `H3CToCiscoTranslator` in `core/h3c_to_cisco.py` (confirmed working in evaluator) |
| GAP-FW-01 | Huawei USG → Topsec no translation path | Address/service/policy objects confirmed as acceptable MANUAL_REVIEW for this minority vendor |

## Active Gap Register

### GAP-RT-01: Cisco → H3C — OSPF/BGP process header not translated

| Field | Value |
|-------|-------|
| **Sample** | `rt-cisco-01` |
| **Target** | `h3c` |
| **Domain** | ROUTER |
| **Residue** | `router ospf`, `router bgp` |
| **Severity** | MEDIUM |
| **Scope** | Cisco `router ospf N` / `router bgp ASN` passes through as-is to H3C output. H3C uses `ospf N` / `bgp ASN` (without `router` prefix). |

**Root cause**: The router rule set (`core/fallback/router_rules.py`) has specific rules for Cisco→Huawei and Huawei→Cisco OSPF/BGP headers, but the Cisco→H3C path is not covered.

**Recommendation**: Add `router ospf N` → `ospf N` and `router bgp ASN` → `bgp ASN` rules to the Cisco→H3C path. Priority: LOW (H3C is the least common target for Cisco router translation pilots). Outside Batch M scope.

---

### GAP-FW-03: Topsec → Huawei USG — Zone name residue

| Field | Value |
|-------|-------|
| **Sample** | `fw-topsec-01` |
| **Target** | `huawei_usg` |
| **Domain** | FIREWALL |
| **Residue** | `zone name` |
| **Severity** | MEDIUM |
| **Scope** | Topsec `zone name <NAME>` passes through as-is instead of translating to `security-zone name <NAME>`. |

**Root cause**: The Topsec→Huawei USG translation covers address objects and service objects, but zone header translation is missing.

**Recommendation**: Add `zone name <NAME>` → `security-zone name <NAME>` rule to Topsec→Huawei USG path. Priority: LOW (address and policy objects are the critical path; zone names often follow a standard convention). Outside Batch M scope.

---

## Priority Summary

| Priority | Count | Gaps |
|----------|-------|------|
| HIGH | 0 | — |
| MEDIUM | 2 | GAP-RT-01, GAP-FW-03 |
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
    "passed": 22,
    "failed": 2,
    "pass_rate": 91.7,
    "by_domain": {
      "FIREWALL": { "total": 8, "passed": 7, "failed": 1 },
      "ROUTER":   { "total": 4, "passed": 3, "failed": 1 },
      "SWITCH":   { "total": 12, "passed": 12, "failed": 0 }
    }
  }
}
```

## Version History

| Date | Change |
|------|--------|
| 2026-06-02 | Batch M expansion: added interface.range, track, management.line module types with semantic_near; rule_translator interface range guard; frontend filter split. Pass rate unchanged 22/24 (91.7%) |
| 2026-05-25 | Batch M close: 22/24 pass rate (91.7%); 4 gaps resolved, 2 active (GAP-RT-01, GAP-FW-03) |
| 2026-05-25 | Initial analysis from Batch L-B corpus evaluation: 8 gaps across all 3 domains |
