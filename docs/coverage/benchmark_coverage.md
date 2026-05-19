# Benchmark Coverage Report

Generated: 2026-05-20 00:43:06
Total cases: 15
Filter: ///

## Tier Distribution

- **smoke**: 3 cases, static 3/3, live 2/3
- **core**: 4 cases, static 4/4, live 3/4
- **full**: 8 cases, static 8/8, live 2/8

## Results

### Static
- Pass: 15
- Fail: 0
- Total: 15

### Live
- Pass: 7
- Fail: 8
- Skip: 0
- Cache: 0 pass / 0 fail / 0 miss

## Case List

| # | Name | Tier | Domain | Source->Target | Risk | Features | Static | Live | Elapsed |
|---|------|------|--------|---------------|------|----------|--------|------|---------|
| 1 | corpus-fw-ipsec-vpn-001 | full | firewall | cisco -> huawei | high | ipsec,nat,acl,interface | PASS | FAIL | 43729 |
| 2 | corpus-fw-nat-001 | full | firewall | huawei -> cisco | high | nat,nat_source,nat_server,acl,security_policy,zone | PASS | FAIL | 120032 |
| 3 | corpus-fw-nat-server-001 | full | firewall | cisco -> huawei | high | nat,acl,interface,static_route | PASS | PASS | 85774 |
| 4 | corpus-fw-nat-sp-001 | full | firewall | huawei -> cisco | high | nat,security_policy,zone,address_object,interface | PASS | FAIL | 31323 |
| 5 | corpus-fw-object-policy-001 | full | firewall | huawei -> cisco | high | address_object,service_object,security_policy,zone,interface | PASS | FAIL | 20491 |
| 6 | corpus-rtr-bgp-001 | core | routing | cisco -> huawei | medium | bgp,route_policy,prefix_list,interface | PASS | FAIL | 35137 |
| 7 | corpus-rtr-ipsec-001 | full | routing | cisco -> huawei | high | ipsec,tunnel,interface,acl | PASS | PASS | 32303 |
| 8 | corpus-rtr-ospf-001 | smoke | routing | cisco -> huawei | medium | ospf,interface,static_route | PASS | PASS | 23585 |
| 9 | corpus-rtr-ospf-bfd-001 | core | routing | huawei -> cisco | medium | ospf,bfd,interface | PASS | PASS | 29 |
| 10 | corpus-rtr-vrf-001 | core | routing | cisco -> huawei | medium | vrf,static_route,interface | PASS | PASS | 18777 |
| 11 | corpus-sw-dhcp-acl-001 | full | switching | cisco -> huawei | high | dhcp,acl,vlan,interface | PASS | FAIL | 22781 |
| 12 | corpus-sw-lacp-001 | smoke | switching | huawei -> cisco | low | lacp,trunk,vlan,interface | PASS | FAIL | 29875 |
| 13 | corpus-sw-mstp-001 | core | switching | cisco -> huawei | medium | stp,vlan,interface | PASS | PASS | 21991 |
| 14 | corpus-sw-stack-001 | full | switching | h3c -> cisco | high | interface,irf | PASS | FAIL | 29845 |
| 15 | corpus-sw-vlan-001 | smoke | switching | huawei -> cisco | low | vlan,interface | PASS | PASS | 13652 |

## Domain Distribution

- firewall: 5
- routing: 5
- switching: 5

## Feature Coverage

- acl
- address_object
- bfd
- bgp
- dhcp
- interface
- ipsec
- irf
- lacp
- nat
- nat_server
- nat_source
- ospf
- prefix_list
- route_policy
- security_policy
- service_object
- static_route
- stp
- trunk
- tunnel
- vlan
- vrf
- zone
