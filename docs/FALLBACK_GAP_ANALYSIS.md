# Fallback Gap Analysis

> **Generated**: `scripts/evaluate_corpus_fallback.py` against `corpus/samples/`
> **Date**: 2026-05-25
> **Pass rate**: 16/24 (66.7%) — 8 known gaps, all non-blocking for Beta

## Summary

| Metric | Value |
|--------|-------|
| Total (sample, target) pairs | 24 |
| Passed (no manual_review leak, no residue, no secret leak) | 16 |
| Failed (real gaps) | 8 |
| Pass rate (residue check) | 66.7% |
| Secret leak rate | 0/24 |

## Gap Register

### GAP-FW-01: Huawei USG → Topsec — No translation path

| Field | Value |
|-------|-------|
| **Sample** | `fw-usg-01` |
| **Target** | `topsec` |
| **Residue** | `security-zone`, `ip address-set`, `ip service-set`, `security-policy` |
| **Severity** | MEDIUM |
| **Scope** | All Huawei USG → Topsec firewall translation is passthrough. Zone, address, service, and policy commands all pass through unchanged, producing Topsec-unparseable syntax. |

**Root cause**: Topsec is a minority firewall vendor. The fallback rule set (`core/fallback/firewall_rules.py`) focuses on the Topsec→Huawei USG direction and Huawei USG→Hillstone direction. The reverse path (Huawei USG→Topsec) has no explicit translation rules.

**Recommendation**: Add Huawei USG→Topsec rules for zone, address, service, and policy. Priority: LOW (Topsec deployments are rare; manual translation with structural pipeline is the primary path).

---

### GAP-FW-02: Hillstone → Huawei USG / Topsec — NAT not guarded

| Field | Value |
|-------|-------|
| **Sample** | `fw-hillstone-01` |
| **Target** | `huawei_usg`, `topsec` |
| **Residue** | `nat ` |
| **Severity** | HIGH |
| **Scope** | Hillstone NAT commands (`nat source`, `nat destination`) pass through unchanged in both Huawei USG and Topsec output. Not marked MANUAL_REVIEW. |

**Root cause**: The dangerous feature guard in the same-vendor passthrough path checks for `nat` keywords, but the cross-vendor path in `core/fallback/firewall_rules.py` does not. Hillstone cross-vendor translation allows unrecognized lines to pass through without the MANUAL_REVIEW marker.

**Recommendation**: Add `nat` keyword check to Hillstone→{huawei_usg, topsec} rule sets. Lines containing `nat` should output `# MANUAL_REVIEW nat ...`. Priority: MEDIUM.

---

### GAP-FW-03: Topsec → Huawei USG — Zone name not translated

| Field | Value |
|-------|-------|
| **Sample** | `fw-topsec-01` |
| **Target** | `huawei_usg` |
| **Residue** | `zone name` |
| **Severity** | MEDIUM |
| **Scope** | Topsec `zone name <NAME>` passes through as-is instead of translating to `security-zone name <NAME>`. |

**Root cause**: The Topsec→Huawei USG translation covers address objects and service objects, but zone header translation is missing.

**Recommendation**: Add `zone name <NAME>` → `security-zone name <NAME>` rule to Topsec→Huawei USG path. Priority: LOW (address and policy objects are the critical path; zone names often follow a standard convention that survives passthrough).

---

### GAP-FW-04: DPtech → Huawei USG / Hillstone — Address not translated, NAT not guarded

| Field | Value |
|-------|-------|
| **Sample** | `fw-dptech-01` |
| **Target** | `huawei_usg`, `hillstone` |
| **Residue** | `object address`, `nat ` |
| **Severity** | HIGH |
| **Scope** | DPtech `object address <NAME> <IP> <MASK>` passes through as-is instead of translating to `ip address-set` (Huawei USG) or `address` (Hillstone) format. NAT commands also pass through unguarded. |

**Root cause**: The DPtech fallback rules (`core/fallback/firewall_rules.py`) handle security-policy translation but skip address object translation. Unknown lines (including NAT) pass through without MANUAL_REVIEW.

**Recommendation**: Add `object address` → target format translation. Add NAT keyword guard. Priority: MEDIUM (DPtech deployments are rare).

---

### GAP-SW-01: H3C → Cisco — VLAN batch not translated

| Field | Value |
|-------|-------|
| **Sample** | `sw-h3c-01` |
| **Target** | `cisco` |
| **Residue** | `vlan batch` |
| **Severity** | MEDIUM |
| **Scope** | H3C `vlan batch N to M` passes through as-is to Cisco output. Cisco does not support `vlan batch`. |

**Root cause**: The switch rules handle Cisco→Huawei VLAN batch translation but the reverse path (H3C→Cisco) is incomplete. The translator sees `vlan batch` as an unrecognized line and passes it through.

**Recommendation**: Add H3C `vlan batch` → Cisco comma-separated `vlan <N>` list translation. Priority: LOW (the H3C→Cisco path through `H3CToCiscoTranslator` in `core/h3c_to_cisco.py` should catch `vlan batch`; verify this both in the translator and in the fallback rule set).

---

### GAP-RT-01: Cisco → H3C — OSPF/BGP process header not translated

| Field | Value |
|-------|-------|
| **Sample** | `rt-cisco-01` |
| **Target** | `h3c` |
| **Residue** | `router ospf`, `router bgp` |
| **Severity** | MEDIUM |
| **Scope** | Cisco `router ospf N` / `router bgp ASN` passes through as-is to H3C output. H3C uses `ospf N` / `bgp ASN` (without `router` prefix). |

**Root cause**: The router rule set (`core/fallback/router_rules.py`) has specific rules for Cisco→Huawei and Huawei→Cisco OSPF/BGP headers, but the Cisco→H3C path is not covered.

**Recommendation**: Add `router ospf N` → `ospf N` and `router bgp ASN` → `bgp ASN` rules to the Cisco→H3C path. Priority: LOW (H3C is the least common target for Cisco router translation pilots).

---

### Priority Summary

| Priority | Count | Gaps |
|----------|-------|------|
| HIGH | 2 | GAP-FW-02, GAP-FW-04 |
| MEDIUM | 4 | GAP-FW-01, GAP-FW-03, GAP-SW-01, GAP-RT-01 |

No secrets leaked across any sample-target pair (0/24).

## Evaluator Data

Full results (JSON): `reports/corpus_fallback_eval.json`
Summary report (Markdown): `reports/CORPUS_FALLBACK_EVAL.md`

```json
// Key excerpt
{
  "summary": {
    "total": 24,
    "passed": 16,
    "failed": 8,
    "pass_rate": 66.7,
    "by_domain": {
      "FIREWALL": { "total": 8, "passed": 2, "failed": 6 },
      "ROUTER":   { "total": 4, "passed": 3, "failed": 1 },
      "SWITCH":   { "total": 12, "passed": 11, "failed": 1 }
    }
  }
}
```

## Version History

| Date | Change |
|------|--------|
| 2026-05-25 | Initial analysis from Batch L-B corpus evaluation: 8 gaps across all 3 domains |
