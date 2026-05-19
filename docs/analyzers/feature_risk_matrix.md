# Feature Risk Matrix — Analyzer Coverage

## Legend

| Column | Meaning |
|--------|---------|
| Feature | Feature name from registry |
| Risk | Overall risk level (high/medium/low) |
| Domains | Applicable domains |
| Has Analyzer | Whether an analyzer exists today |
| Priority | Planned analyzer priority |
| Planned | Analyzer planned for this feature |
| Bench Cases | Linked benchmark case count |
| Test Cases | Planned unit tests for this analyzer |

## Matrix

| # | Feature | Risk | Domains | Has Analyzer | Priority | Planned | Bench | Tests |
|---|---------|------|---------|-------------|----------|---------|-------|-------|
| 1 | bfd | MEDIUM | routing | ❌ | p2 | BfdAnalyzer | 1 | 2 |
| 2 | dhcp | LOW | routing,switching | ❌ | p1 | DhcpAnalyzer | 1 | 2 |
| 3 | ipsec | HIGH | routing,firewall | ❌ | p0 | IpsecAnalyzer | 1 | 4 |
| 4 | lacp | LOW | switching | ❌ | p2 | LacpAnalyzer | 1 | 2 |
| 5 | object | LOW | firewall | ❌ | p1 | ObjectAnalyzer | 5 | 3 |
| 6 | qos | MEDIUM | routing,switching | ❌ | p0 | QosAnalyzer | 2 | 4 |
| 7 | route_policy | MEDIUM | routing | ❌ | p0 | RoutePolicyAnalyzer | 1 | 6 |
| 8 | stp | MEDIUM | switching | ❌ | p2 | StpAnalyzer | 1 | 2 |
| 9 | tunnel | MEDIUM | routing | ❌ | p2 | TunnelAnalyzer | 1 | 2 |
| 10 | vrf | MEDIUM | routing | ❌ | p2 | VrfAnalyzer | 1 | 2 |
| 11 | vrrp | MEDIUM | routing,switching | ❌ | p1 | VrrpAnalyzer | 1 | 2 |

## Existing Analyzers

| Analyzer | Feature | Status | Lines of Code |
|----------|---------|--------|--------------:|
| NatAnalyzer | nat | ✅ Production | 381 |
| SecurityPolicyAnalyzer | security_policy | ✅ Production | 528 |
| AclAnalyzer | acl | ✅ Production | ~300 |
| NoopAnalyzer | (fallback) | ✅ Production | ~30 |

