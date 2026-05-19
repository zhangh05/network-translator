# Analyzer Roadmap

## Milestones

| Phase | Scope | Analyzers | Target Date | Bench Cases | Dependencies |
|-------|-------|-----------|-------------|-------------|-------------|

| Phase 5-A | P0 Analyzer Core | RoutePolicyAnalyzer ✓, IpsecAnalyzer ✓, QosAnalyzer ✓ | 4 bench, 14+33 tests | ✅ Completed — close gate passed |
| Phase 5-B | P1 Analyzer Expansion | ObjectAnalyzer ✓, VrrpAnalyzer ✓, DhcpAnalyzer ✓ | 7 bench, 30 tests | ✅ Completed — close gate passed |
| Phase 5-C | P2 Analyzer Completion | VrfAnalyzer ✓, TunnelAnalyzer ✓, BfdAnalyzer ✓, StpAnalyzer ✓, LacpAnalyzer ✓ | 10 bench, 55 tests | ✅ Completed — close gate passed |

## Feature → Bench Case Mapping

| Analyzer | Feature | Linked Bench Cases |
|----------|---------|-------------------|
| BfdAnalyzer | bfd | `h3c-routing-ospf-bfd-to-cisco` |
| DhcpAnalyzer | dhcp | `cisco-routing-dhcp-to-h3c` |
| IpsecAnalyzer | ipsec | `cisco-firewall-ipsec-to-huawei` |
| LacpAnalyzer | lacp | `h3c-switching-lacp-to-cisco` |
| ObjectAnalyzer | object | `cisco-firewall-security-policy-to-h3c`, `h3c-firewall-nat-server-to-huawei`, `h3c-firewall-service-object-to-huawei`, `huawei-firewall-security-policy-deny-to-h3c`, `huawei-firewall-zone-address-to-cisco` |
| QosAnalyzer | qos | `huawei-routing-qos-to-cisco`, `huawei-switching-qos-to-h3c` |
| RoutePolicyAnalyzer | route_policy | `huawei-routing-bgp-route-policy-to-cisco` |
| StpAnalyzer | stp | `huawei-switching-stp-to-cisco` |
| TunnelAnalyzer | tunnel | `cisco-routing-tunnel-to-huawei` |
| VrfAnalyzer | vrf | `cisco-routing-vrf-static-to-huawei` |
| VrrpAnalyzer | vrrp | `huawei-routing-vrrp-to-cisco` |

## Total Effort Estimate

| Phase | Analyzers | Planned Cases | Bench Linked | Dependency |
|-------|-----------|--------------:|-------------:|-----------|
| Phase 5-A | RoutePolicyAnalyzer, IpsecAnalyzer, QosAnalyzer | 14 | dedicated cases | framework ready |
| Phase 5-B | ObjectAnalyzer, VrrpAnalyzer, DhcpAnalyzer | 30 | shared cases | Phase 5-A done |
| Phase 5-C | VrfAnalyzer, TunnelAnalyzer, BfdAnalyzer, StpAnalyzer, LacpAnalyzer | 10 | shared cases | Phase 5-B done |
| **Total** | **14 analyzers (+1 NoopAnalyzer)** | **54** | **35 bench cases** | **All 5 phases complete** |
