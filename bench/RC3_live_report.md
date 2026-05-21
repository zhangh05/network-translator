# Live Failure Backlog

Generated: 2026-05-21 15:11:18
Source: bench/live_report.json
Total failures: 4

## Priority Distribution

- **P0**: 3
- **P1**: 0
- **P2**: 1

## Category Distribution

- **validator_false_negative**: 3
- **unknown**: 1

## Backlog

| Pri | Case | Domain | Src→Tgt | Features | Category | Reason | Deployable | MRev |
|-----|------|--------|---------|----------|----------|--------|------------|------|
| P0 | corpus-fw-nat-001 | firewall | huawei→cisco | nat, nat_source, nat_server, acl, securi | validator_false_negative | deployable expected=True got=False | ✗ | ⚠ |
| P0 | corpus-fw-nat-server-001 | firewall | cisco→huawei | nat, acl, interface, static_route | validator_false_negative | missing must_include: nat server; deployable expected=True g | ✗ | ⚠ |
| P0 | corpus-fw-object-policy-001 | firewall | huawei→cisco | address_object, service_object, security | validator_false_negative | deployable expected=False got=True; expected manual_review_r | ✓ | ✓ |
| P2 | corpus-rtr-ipsec-001 | routing | cisco→huawei | ipsec, tunnel, interface, acl | unknown | HTTP 500 | ? | ? |

Summary JSON: /root/network-translator/reports/live_summary.json
