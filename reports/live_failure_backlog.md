# Live Failure Backlog

Generated: 2026-05-21 18:09:17
Source: bench/live_report.json
Total failures: 5

## Priority Distribution

- **P0**: 1
- **P1**: 3
- **P2**: 1

## Category Distribution

- **llm_quality_issue**: 3
- **infra_issue**: 1
- **annotation_issue**: 1

## Backlog

| Pri | Case | Domain | Src→Tgt | Features | Category | Reason | Deployable | MRev |
|-----|------|--------|---------|----------|----------|--------|------------|------|
| P0 | corpus-sw-mstp-001 | switching | cisco→huawei | stp, vlan, interface | infra_issue | HTTP 500 | ? | ? |
| P1 | corpus-fw-nat-server-001 | firewall | cisco→huawei | nat, acl, interface, static_route | llm_quality_issue | deployable expected=True got=False | ✗ | ⚠ |
| P1 | corpus-rtr-bgp-001 | routing | cisco→huawei | bgp, route_policy, prefix_list, interfac | llm_quality_issue | missing must_include: ip-prefix | ✓ | ⚠ |
| P1 | corpus-sw-lacp-001 | switching | huawei→cisco | lacp, trunk, vlan, interface | llm_quality_issue | deployable expected=True got=False | ✗ | ⚠ |
| P2 | corpus-fw-object-policy-001 | firewall | huawei→cisco | address_object, service_object, security | annotation_issue | expected manual_review_required=True but system returned Fal | ✓ | ✓ |

Summary JSON: /root/network-translator/reports/live_summary.json
