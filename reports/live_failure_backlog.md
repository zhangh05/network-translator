# Live Failure Backlog

Generated: 2026-05-20 01:07:28
Source: bench/live_report.json
Total failures: 8

## Priority Distribution

- **P0**: 2
- **P1**: 6
- **P2**: 0

## Category Distribution

- **llm_quality_issue**: 5
- **validator_false_negative**: 2
- **llm_timeout**: 1

## Backlog

| Pri | Case | Domain | Category | Errors |
|-----|------|--------|----------|--------|
| P0 | corpus-rtr-bgp-001 | corpus | validator_false_negative | missing must_include: ip ip-prefix; contains forbidden: ip prefix-list |
| P0 | corpus-sw-stack-001 | corpus | validator_false_negative | contains forbidden: irf member; contains forbidden: irf-port |
| P1 | corpus-fw-ipsec-vpn-001 | corpus | llm_quality_issue | missing must_include: ipsec policy |
| P1 | corpus-fw-nat-001 | corpus | llm_timeout | error |
| P1 | corpus-fw-nat-sp-001 | corpus | llm_quality_issue | missing must_include: nat (inside,outside) dynamic; missing must_include: access |
| P1 | corpus-fw-object-policy-001 | corpus | llm_quality_issue | missing must_include: access-list extended |
| P1 | corpus-sw-dhcp-acl-001 | corpus | llm_quality_issue | missing must_include: dhcp snooping trusted |
| P1 | corpus-sw-lacp-001 | corpus | llm_quality_issue | contains forbidden: lacp-static |

Summary JSON: /root/network-translator/reports/live_summary.json
