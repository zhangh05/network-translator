# Benchmark Coverage Report

Generated: 2026-05-20 03:18:59
Total cases: 15
Filter: ///

## Tier Distribution

- **smoke**: 3 cases, static 3/3, live 3/3
- **core**: 4 cases, static 4/4, live 2/4
- **full**: 8 cases, static 8/8, live 7/8

## Results

### Static
- Pass: 15
- Fail: 0
- Total: 15

### Live
- Pass: 12
- Fail: 3
- Skip: 0
- Cache: 0 pass / 0 fail / 0 miss

## Case List

| # | Name | Tier | Domain | Source->Target | Risk | Features | Static | Live | Elapsed |
|---|------|------|--------|---------------|------|----------|--------|------|---------|
| 1 | corpus-fw-ipsec-vpn-001 | full | firewall | cisco -> huawei | high | ipsec,nat,acl,interface | PASS | PASS | 43967 |
| 2 | corpus-fw-nat-001 | full | firewall | huawei -> cisco | high | nat,nat_source,nat_server,acl,security_policy,zone | PASS | PASS | 33216 |
| 3 | corpus-fw-nat-server-001 | full | firewall | cisco -> huawei | high | nat,acl,interface,static_route | PASS | PASS | 32685 |
| 4 | corpus-fw-nat-sp-001 | full | firewall | huawei -> cisco | high | nat,security_policy,zone,address_object,interface | PASS | PASS | 30750 |
| 5 | corpus-fw-object-policy-001 | full | firewall | huawei -> cisco | high | address_object,service_object,security_policy,zone,interface | PASS | FAIL | 18306 |
| 6 | corpus-rtr-bgp-001 | core | routing | cisco -> huawei | medium | bgp,route_policy,prefix_list,interface | PASS | FAIL | 37808 |
| 7 | corpus-rtr-ipsec-001 | full | routing | cisco -> huawei | high | ipsec,tunnel,interface,acl | PASS | PASS | 27493 |
| 8 | corpus-rtr-ospf-001 | smoke | routing | cisco -> huawei | medium | ospf,interface,static_route | PASS | PASS | 26294 |
| 9 | corpus-rtr-ospf-bfd-001 | core | routing | huawei -> cisco | medium | ospf,bfd,interface | PASS | PASS | 24743 |
| 10 | corpus-rtr-vrf-001 | core | routing | cisco -> huawei | medium | vrf,static_route,interface | PASS | PASS | 36508 |
| 11 | corpus-sw-dhcp-acl-001 | full | switching | cisco -> huawei | high | dhcp,acl,vlan,interface | PASS | PASS | 31549 |
| 12 | corpus-sw-lacp-001 | smoke | switching | huawei -> cisco | low | lacp,trunk,vlan,interface | PASS | PASS | 28319 |
| 13 | corpus-sw-mstp-001 | core | switching | cisco -> huawei | medium | stp,vlan,interface | PASS | FAIL | 22705 |
| 14 | corpus-sw-stack-001 | full | switching | h3c -> cisco | high | interface,irf | PASS | PASS | 20085 |
| 15 | corpus-sw-vlan-001 | smoke | switching | huawei -> cisco | low | vlan,interface | PASS | PASS | 25039 |

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
