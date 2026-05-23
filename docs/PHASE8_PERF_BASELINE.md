# Phase 8A: Performance Baseline Report

> Generated at 2026-05-23 18:47:40
> Python 3.9.6
> Commit: 826ae9ab78228adb7ddd72371a29ccdf7c85cfd6

## Summary

| Metric | Value |
|--------|-------|
| Total tasks | 20 |
| Passed | 11 |
| Failed (non-deployable) | 9 |
| Errors | 0 |
| Total wall time | 2.1ms |
| Mean per task | 0.1ms |
| Min task time | 0.1ms |
| Max task time | 0.5ms |
| Mean validate phase | 0.1ms |
| Throughput | 9615.38 tasks/sec |

## Task Details

| # | Name | Source | Target | Domain | Time | Issues | Status |
|---|------|--------|--------|--------|------|--------|--------|
| 1 | h3c_to_cisco_vlan_svi_acl | h3c | cisco | switch | 0.5ms | 0 | PASS |
| 2 | cisco_to_h3c_vlan | cisco | h3c | switch | 0.3ms | 1 | FAIL |
| 3 | huawei_to_cisco_stp_lag | huawei | cisco | switch | 0.1ms | 0 | PASS |
| 4 | ruijie_to_cisco_acl | ruijie | cisco | switch | 0.1ms | 1 | PASS |
| 5 | h3c_to_ruijie_vlan_static | h3c | ruijie | switch | 0.1ms | 0 | PASS |
| 6 | huawei_to_h3c_basic_vlan | huawei | h3c | switch | 0.1ms | 1 | FAIL |
| 7 | cisco_to_huawei_svi_static | cisco | huawei | switch | 0.1ms | 1 | FAIL |
| 8 | ruijie_to_h3c_empty | ruijie | h3c | switch | 0.1ms | 1 | FAIL |
| 9 | h3c_to_huawei_ospf_deep | h3c | huawei | router | 0.1ms | 1 | FAIL |
| 10 | cisco_to_huawei_bgp_vrf | cisco | huawei | router | 0.1ms | 1 | FAIL |
| 11 | huawei_to_cisco_ospf_mismatch | huawei | cisco | router | 0.1ms | 1 | FAIL |
| 12 | cisco_to_h3c_ospf_insufficient | cisco | h3c | router | 0.1ms | 2 | FAIL |
| 13 | h3c_to_cisco_static_route | h3c | cisco | router | 0.1ms | 0 | PASS |
| 14 | ruijie_to_huawei_route_only | ruijie | huawei | router | 0.1ms | 1 | FAIL |
| 15 | huawei_vrp_to_cisco_router_basic | huawei | cisco | router | 0.1ms | 0 | PASS |
| 16 | huawei_usg_to_hillstone_basic | huawei_usg | hillstone | firewall | 0.1ms | 0 | PASS |
| 17 | hillstone_to_huawei_usg_empty | hillstone | huawei_usg | firewall | 0.1ms | 0 | PASS |
| 18 | topsec_to_hillstone_zones | topsec | hillstone | firewall | 0.1ms | 0 | PASS |
| 19 | dptech_to_usg_policy | dptech | huawei_usg | firewall | 0.1ms | 0 | PASS |
| 20 | usg_to_topsec_objects | huawei_usg | topsec | firewall | 0.1ms | 0 | PASS |

## Domain Distribution

- **firewall**: 5 tasks, avg 0.1ms
- **router**: 7 tasks, avg 0.1ms
- **switch**: 8 tasks, avg 0.2ms

## Notes

- All timings are wall-clock for the validate-only pipeline (no LLM calls).
- Tasks use synthetic IR data constructed from dataclass to_dict().
- The batch runner is in `core/batch/` — see `scripts/run_baseline.py`.
- Full-pipeline throughput (parse + translate + validate) will be lower
  due to LLM API latency.
