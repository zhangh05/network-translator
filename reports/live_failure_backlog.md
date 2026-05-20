# Live Failure Backlog

Generated: 2026-05-21 02:05:58
Source: bench/live_report.json
Total failures: 7

## Priority Distribution

- **P0**: 3
- **P1**: 3
- **P2**: 1

## Category Distribution

- **validator_false_negative**: 3
- **llm_quality_issue**: 3
- **unknown**: 1

## Backlog

| Pri | Case | Domain | Src→Tgt | Features | Category | Reason | Deployable | MRev |
|-----|------|--------|---------|----------|----------|--------|------------|------|
| P0 | corpus-fw-nat-001 | firewall | huawei→cisco | nat, nat_source, nat_server, acl, securi | validator_false_negative | missing must_include: access-group; deployable expected=True | ✗ | ⚠ |
| P0 | corpus-rtr-ipsec-001 | routing | cisco→huawei | ipsec, tunnel, interface, acl | validator_false_negative | deployable expected=False got=True; expected manual_review_r | ✓ | ✓ |
| P0 | corpus-sw-vlan-001 | switching | huawei→cisco | vlan, interface | validator_false_negative | deployable expected=True got=False | ✗ | ⚠ |
| P1 | corpus-rtr-vrf-001 | routing | cisco→huawei | vrf, static_route, interface | llm_quality_issue | missing must_include: ip route-static vpn-instance | ✓ | ✓ |
| P1 | corpus-sw-dhcp-acl-001 | switching | cisco→huawei | dhcp, acl, vlan, interface | llm_quality_issue | missing must_include: dhcp snooping trust | ✗ | ⚠ |
| P1 | corpus-sw-mstp-001 | switching | cisco→huawei | stp, vlan, interface | llm_quality_issue | missing must_include: stp region-name | ✓ | ✓ |
| P2 | corpus-sw-stack-001 | switching | h3c→cisco | interface, irf | unknown | fatal capability_gaps: [{'details': {}, 'feature': 'irf', 's | ✗ | ⚠ |

Summary JSON: /root/network-translator/reports/live_summary.json
