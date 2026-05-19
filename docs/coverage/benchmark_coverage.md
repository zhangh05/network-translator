# Benchmark Coverage Report

Generated: 2026-05-19 17:13:06
Total cases: 35
Filter: ///

## Tier Distribution

- **smoke**: 12 cases, static 12/12, live 0/0
- **core**: 14 cases, static 14/14, live 0/0
- **full**: 9 cases, static 9/9, live 0/0

## Results

### Static
- Pass: 35
- Fail: 0
- Total: 35

### Live
- Pass: 0
- Fail: 0
- Skip: 35
- Cache: 0 pass / 0 fail / 0 miss

## Case List

| # | Name | Tier | Domain | Source->Target | Risk | Features | Static | Live | Elapsed |
|---|------|------|--------|---------------|------|----------|--------|------|---------|
| 1 | huawei-firewall-zone-address-to-cisco | core | firewall | huawei -> cisco | medium | zone,address_object | PASS | SKIP |  |
| 2 | h3c-firewall-service-object-to-huawei | smoke | firewall | h3c -> huawei | low | service_object,address_object | PASS | SKIP |  |
| 3 | cisco-firewall-security-policy-to-h3c | full | firewall | cisco -> h3c | high | security_policy,address_object,service_object | PASS | SKIP |  |
| 4 | huawei-firewall-nat-source-to-cisco | full | firewall | huawei -> cisco | high | nat | PASS | SKIP |  |
| 5 | h3c-firewall-nat-server-to-huawei | full | firewall | h3c -> huawei | high | nat,zone,address_object | PASS | SKIP |  |
| 6 | cisco-firewall-acl-to-huawei | core | firewall | cisco -> huawei | medium | acl,zone | PASS | SKIP |  |
| 7 | cisco-firewall-ipsec-to-huawei | full | firewall | cisco -> huawei | high | ipsec | PASS | SKIP |  |
| 8 | h3c-firewall-static-route-to-cisco | smoke | firewall | h3c -> cisco | low | static_route,interface | PASS | SKIP |  |
| 9 | cisco-firewall-syslog-to-huawei | smoke | firewall | cisco -> huawei | low | syslog | PASS | SKIP |  |
| 10 | huawei-firewall-security-policy-deny-to-h3c | core | firewall | huawei -> h3c | medium | security_policy,zone,address_object | PASS | SKIP |  |
| 11 | h3c-firewall-nat-missing-zone-to-huawei | full | firewall | h3c -> huawei | high | nat | PASS | SKIP |  |
| 12 | cisco-asa-unsupported-to-huawei | full | firewall | cisco -> huawei | high | security_policy,nat | PASS | SKIP |  |
| 13 | h3c-routing-import-bgp-missing-as-to-cisco | full | routing | h3c -> cisco | high | bgp,ospf | PASS | SKIP |  |
| 14 | cisco-routing-ospf-incomplete-to-h3c | full | routing | cisco -> h3c | high | ospf | PASS | SKIP |  |
| 15 | h3c-routing-interface-static-to-cisco | smoke | routing | h3c -> cisco | low | interface,static_route | PASS | SKIP |  |
| 16 | cisco-routing-ospf-to-huawei | core | routing | cisco -> huawei | medium | ospf | PASS | SKIP |  |
| 17 | huawei-routing-bgp-route-policy-to-cisco | core | routing | huawei -> cisco | medium | bgp,route_policy | PASS | SKIP |  |
| 18 | cisco-routing-acl-pbr-to-h3c | core | routing | cisco -> h3c | medium | acl,pbr | PASS | SKIP |  |
| 19 | cisco-routing-vrf-static-to-huawei | core | routing | cisco -> huawei | medium | vrf,static_route | PASS | SKIP |  |
| 20 | huawei-routing-vrrp-to-cisco | smoke | routing | huawei -> cisco | low | vrrp | PASS | SKIP |  |
| 21 | cisco-routing-dhcp-to-h3c | smoke | routing | cisco -> h3c | low | dhcp | PASS | SKIP |  |
| 22 | huawei-routing-qos-to-cisco | core | routing | huawei -> cisco | medium | qos | PASS | SKIP |  |
| 23 | cisco-routing-tunnel-to-huawei | core | routing | cisco -> huawei | medium | tunnel | PASS | SKIP |  |
| 24 | h3c-routing-ospf-bfd-to-cisco | core | routing | h3c -> cisco | medium | ospf,bfd | PASS | SKIP |  |
| 25 | huawei-switching-to-cisco-ios-no-vlan-database | full | switching | huawei -> cisco | high | vlan,interface | PASS | SKIP |  |
| 26 | cisco-switching-vlan-access-to-h3c | smoke | switching | cisco -> h3c | low | vlan | PASS | SKIP |  |
| 27 | h3c-switching-trunk-to-cisco | smoke | switching | h3c -> cisco | low | trunk | PASS | SKIP |  |
| 28 | huawei-switching-stp-to-cisco | core | switching | huawei -> cisco | medium | stp | PASS | SKIP |  |
| 29 | h3c-switching-lacp-to-cisco | smoke | switching | h3c -> cisco | low | lacp | PASS | SKIP |  |
| 30 | cisco-switching-acl-to-huawei | core | switching | cisco -> huawei | medium | acl | PASS | SKIP |  |
| 31 | huawei-switching-qos-to-h3c | core | switching | huawei -> h3c | medium | qos | PASS | SKIP |  |
| 32 | cisco-switching-lldp-to-huawei | smoke | switching | cisco -> huawei | low | lldp | PASS | SKIP |  |
| 33 | cisco-switching-cdp-to-huawei | smoke | switching | cisco -> huawei | low | cdp | PASS | SKIP |  |
| 34 | h3c-switching-stack-to-cisco | core | switching | h3c -> cisco | medium | stack | PASS | SKIP |  |
| 35 | huawei-switching-interface-to-h3c | smoke | switching | huawei -> h3c | low | interface | PASS | SKIP |  |

## Domain Distribution

- firewall: 12
- routing: 12
- switching: 11

## Feature Coverage

- acl
- address_object
- bfd
- bgp
- cdp
- dhcp
- interface
- ipsec
- lacp
- lldp
- nat
- ospf
- pbr
- qos
- route_policy
- security_policy
- service_object
- stack
- static_route
- stp
- syslog
- trunk
- tunnel
- vlan
- vrf
- vrrp
- zone
