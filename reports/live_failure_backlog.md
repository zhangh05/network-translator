# Live Failure Backlog

Generated: 2026-05-21 12:44:32
Source: bench/live_report.json
Total failures: 5

## Priority Distribution

- **P0**: 4
- **P1**: 1
- **P2**: 0

## Category Distribution

- **validator_false_negative**: 4
- **llm_quality_issue**: 1

## Backlog

| Pri | Case | Domain | Src→Tgt | Features | Category | Reason | Deployable | MRev |
|-----|------|--------|---------|----------|----------|--------|------------|------|
| P0 | corpus-fw-ipsec-vpn-001 | firewall | cisco→huawei | ipsec, nat, acl, interface | validator_false_negative | deployable expected=False got=True; expected manual_review_r | ✓ | ✓ |
| P0 | corpus-fw-nat-001 | firewall | huawei→cisco | nat, nat_source, nat_server, acl, securi | validator_false_negative | deployable expected=True got=False; unexpected warning capab | ✗ | ⚠ |
| P0 | corpus-fw-nat-server-001 | firewall | cisco→huawei | nat, acl, interface, static_route | validator_false_negative | deployable expected=False got=True; expected manual_review_r | ✓ | ✓ |
| P0 | corpus-sw-dhcp-acl-001 | switching | cisco→huawei | dhcp, acl, vlan, interface | validator_false_negative | deployable expected=False got=True; expected manual_review_r | ✓ | ✓ |
| P1 | corpus-fw-nat-sp-001 | firewall | huawei→cisco | nat, security_policy, zone, address_obje | llm_quality_issue | contains forbidden: nat policy | ✗ | ⚠ |

Summary JSON: /root/network-translator/reports/live_summary.json
