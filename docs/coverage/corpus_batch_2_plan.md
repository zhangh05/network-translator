# Step 53 — Corpus Batch 2 Expansion Plan

## Current Coverage (15 entries)
| Vendor | Count | Missing |
|--------|-------|---------|
| Cisco | 8 | — |
| Huawei | 6 | — |
| H3C | 1 | Low H3C coverage |
| **Ruijie** | **0** | **Entirely missing** |

## Batch 2 Target: 15 new entries

### Priority 1 — Ruijie (3 entries)
Vendor completely absent from corpus. Ruijie is a major Chinese enterprise vendor.

| # | Domain | Feature | Source | Notes |
|---|--------|---------|--------|-------|
| 1 | routing | bgp + static_route | Public docs/labs | Basic BGP with static routes |
| 2 | switching | vlan + trunk + interface | Public docs | VLAN config with trunk ports |
| 3 | firewall | acl + zone + nat | Public docs | ACL and zone-based NAT |

### Priority 2 — H3C expansion (3 entries)
H3C currently has only 1 entry (IRF stacking).

| # | Domain | Feature | Notes |
|---|--------|---------|-------|
| 4 | routing | ospf + bfd | Single-area OSPF with BFD |
| 5 | switching | lacp + vlan | Eth-Trunk with LACP |
| 6 | routing | bgp + vrf | BGP VRF-lite |

### Priority 3 — Feature coverage (6 entries)
Features with zero or low coverage.

| # | Source | Target | Feature | Notes |
|---|--------|--------|---------|-------|
| 7 | Cisco IOS | Huawei VRP | vrrp | HSRP → VRRP translation |
| 8 | Huawei VRP | Cisco IOS | vrrp | VRRP → HSRP translation |
| 9 | H3C Comware | Cisco IOS | qos | QoS traffic policy |
| 10 | Cisco IOS | Huawei VRP | tunnel | GRE tunnel |
| 11 | Huawei VRP | H3C Comware | multicast | PIM/IGMP |
| 12 | Cisco ASA | Huawei USG | ipsec | ASA IPsec → USG |

### Priority 4 — Complex cross-feature (3 entries)
Multiple interacting features.

| # | Source | Target | Features | Notes |
|---|--------|--------|----------|-------|
| 13 | Cisco IOS | Huawei VRP | nat + acl + static_route | PAT with ACL + route |
| 14 | Huawei USG | Cisco ASA | security_policy + nat + zone | Full policy + NAT |
| 15 | Cisco Nexus | Huawei VRP | vpc + lacp + vlan | vPC + LACP + VLAN |

## Process per entry
```
collect public/lab config (no real customer data)
→ sanitize (198.18.x.x IPs, __REDACTED__ secrets)
→ write annotation.json (classification, expected translation, verification)
→ corpus_validate
→ corpus_to_bench
→ static bench
→ live bench (if API available)
```

## Completion Criteria
- 15 new entries: 4 Ruijie + 3 H3C + 6 feature coverage + 2 complex
- corpus: 15 → 30 entries
- bench cases: 50 → 65
- No real customer data committed
