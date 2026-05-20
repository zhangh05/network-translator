# Coverage Matrix

Generated: 2026-05-20 17:52:08
Corpus entries: 15
Registered features: 44

Unique features in corpus: 24

## Domain × Source Vendor Coverage

| Domain | Vendor | Cases | Target Vendors | Features |
|--------|--------|-------|----------------|----------|
| routing | cisco | 4 | huawei | acl, bgp, interface, ipsec, ospf, prefix_list, route_policy, static_route, tunnel, vrf |
| routing | huawei | 1 | cisco | bfd, interface, ospf |
| switching | cisco | 2 | huawei | acl, dhcp, interface, stp, vlan |
| switching | huawei | 2 | cisco | interface, lacp, trunk, vlan |
| switching | h3c | 1 | cisco | interface, irf |
| firewall | cisco | 2 | huawei | acl, interface, ipsec, nat, static_route |
| firewall | huawei | 3 | cisco | acl, address_object, interface, nat, nat_server, nat_source, security_policy, service_object, zone |

### Domain Summary

- **routing**: 5 cases
- **switching**: 5 cases
- **firewall**: 5 cases

## Feature Priority Coverage

| Priority | Registered | In Corpus | Coverage % | Missing |
|----------|------------|-----------|------------|---------|
| P0 | 21 | 18 | 86% | isis, system, vrrp |
| P1 | 18 | 3 | 17% | aaa, cdp, etherchannel, ipv6, lldp, local_user, multicast, ntp, pbr, poe, port_channel, qos, snmp, ssh, syslog |
| P2 | 5 | 1 | 20% | dcn, evpn, mpls, vxlan |

## Feature × Vendor Coverage (Source)

| Feature | Pri | Risk | Cisco | Huawei | H3c | Ruijie | Hillstone | Topsec | Dbappsecurity | Dptech | Total |
|---------|-----|------|--------|--------|--------|--------|--------|--------|--------|--------|-------|
| acl | P0 | High | **4** | **1** | ~0~ | — | — | — | — | — | 5 |
| address_object | P0 | Low | — | 2 | — | — | — | — | — | — | 2 |
| bgp | P0 | Medium | **1** | ~0~ | ~0~ | — | — | — | — | — | 1 |
| dhcp | P0 | Low | **1** | ~0~ | ~0~ | — | — | — | — | — | 1 |
| interface | P0 | Medium | **8** | **5** | **1** | — | — | — | — | — | 14 |
| ipsec | P0 | High | **2** | ~0~ | ~0~ | — | — | — | — | — | 2 |
| isis | P0 | Medium | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| lacp | P0 | Low | — | 1 | — | — | — | — | — | — | 1 |
| nat | P0 | High | **2** | **2** | ~0~ | — | — | — | — | — | 4 |
| ospf | P0 | Medium | **1** | **1** | ~0~ | — | — | — | — | — | 2 |
| prefix_list | P0 | Low | **1** | ~0~ | ~0~ | — | — | — | — | — | 1 |
| route_policy | P0 | Medium | **1** | ~0~ | ~0~ | — | — | — | — | — | 1 |
| security_policy | P0 | High | ~0~ | **3** | ~0~ | — | — | — | — | — | 3 |
| service_object | P0 | Low | — | 1 | — | — | — | — | — | — | 1 |
| static_route | P0 | Low | **3** | ~0~ | ~0~ | — | — | — | — | — | 3 |
| stp | P0 | Medium | **1** | ~0~ | ~0~ | — | — | — | — | — | 1 |
| system | P0 | Low | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| trunk | P0 | Low | — | 1 | — | — | — | — | — | — | 1 |
| vlan | P0 | Low | **2** | **2** | ~0~ | — | — | — | — | — | 4 |
| vrrp | P0 | Medium | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| zone | P0 | Low | — | 3 | — | — | — | — | — | — | 3 |
| aaa | P1 | Medium | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| bfd | P1 | Medium | ~0~ | **1** | ~0~ | — | — | — | — | — | 1 |
| cdp | P1 | Low | ~0~ | — | — | — | — | — | — | — | 0 |
| etherchannel | P1 | Low | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| ipv6 | P1 | Medium | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| lldp | P1 | Low | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| local_user | P1 | Low | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| multicast | P1 | Medium | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| ntp | P1 | Low | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| pbr | P1 | Medium | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| poe | P1 | Low | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| port_channel | P1 | Low | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| qos | P1 | Medium | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| snmp | P1 | Low | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| ssh | P1 | Low | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| syslog | P1 | Low | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| tunnel | P1 | Medium | **1** | ~0~ | ~0~ | — | — | — | — | — | 1 |
| vrf | P1 | Medium | **1** | ~0~ | ~0~ | — | — | — | — | — | 1 |
| dcn | P2 | Medium | — | ~0~ | — | — | — | — | — | — | 0 |
| evpn | P2 | High | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| irf | P2 | Medium | — | — | **1** | — | — | — | — | — | 1 |
| mpls | P2 | High | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |
| vxlan | P2 | High | ~0~ | ~0~ | ~0~ | — | — | — | — | — | 0 |

## Feature × Vendor Coverage (Target)

| Feature | Pri | Cisco | Huawei | H3c | Ruijie | Hillstone | Topsec | Dbappsecurity | Dptech | Total |
|---------|-----|--------|--------|--------|--------|--------|--------|--------|--------|-------|
| acl | P0 | 1 | 4 | — | — | — | — | — | — | 5 |
| address_object | P0 | 2 | — | — | — | — | — | — | — | 2 |
| bgp | P0 | — | 1 | — | — | — | — | — | — | 1 |
| dhcp | P0 | — | 1 | — | — | — | — | — | — | 1 |
| interface | P0 | 6 | 8 | — | — | — | — | — | — | 14 |
| ipsec | P0 | — | 2 | — | — | — | — | — | — | 2 |
| isis | P0 | — | — | — | — | — | — | — | — | 0 |
| lacp | P0 | 1 | — | — | — | — | — | — | — | 1 |
| nat | P0 | 2 | 2 | — | — | — | — | — | — | 4 |
| ospf | P0 | 1 | 1 | — | — | — | — | — | — | 2 |
| prefix_list | P0 | — | 1 | — | — | — | — | — | — | 1 |
| route_policy | P0 | — | 1 | — | — | — | — | — | — | 1 |
| security_policy | P0 | 3 | — | — | — | — | — | — | — | 3 |
| service_object | P0 | 1 | — | — | — | — | — | — | — | 1 |
| static_route | P0 | — | 3 | — | — | — | — | — | — | 3 |
| stp | P0 | — | 1 | — | — | — | — | — | — | 1 |
| system | P0 | — | — | — | — | — | — | — | — | 0 |
| trunk | P0 | 1 | — | — | — | — | — | — | — | 1 |
| vlan | P0 | 2 | 2 | — | — | — | — | — | — | 4 |
| vrrp | P0 | — | — | — | — | — | — | — | — | 0 |
| zone | P0 | 3 | — | — | — | — | — | — | — | 3 |
| aaa | P1 | — | — | — | — | — | — | — | — | 0 |
| bfd | P1 | 1 | — | — | — | — | — | — | — | 1 |
| cdp | P1 | — | — | — | — | — | — | — | — | 0 |
| etherchannel | P1 | — | — | — | — | — | — | — | — | 0 |
| ipv6 | P1 | — | — | — | — | — | — | — | — | 0 |
| lldp | P1 | — | — | — | — | — | — | — | — | 0 |
| local_user | P1 | — | — | — | — | — | — | — | — | 0 |
| multicast | P1 | — | — | — | — | — | — | — | — | 0 |
| ntp | P1 | — | — | — | — | — | — | — | — | 0 |
| pbr | P1 | — | — | — | — | — | — | — | — | 0 |
| poe | P1 | — | — | — | — | — | — | — | — | 0 |
| port_channel | P1 | — | — | — | — | — | — | — | — | 0 |
| qos | P1 | — | — | — | — | — | — | — | — | 0 |
| snmp | P1 | — | — | — | — | — | — | — | — | 0 |
| ssh | P1 | — | — | — | — | — | — | — | — | 0 |
| syslog | P1 | — | — | — | — | — | — | — | — | 0 |
| tunnel | P1 | — | 1 | — | — | — | — | — | — | 1 |
| vrf | P1 | — | 1 | — | — | — | — | — | — | 1 |
| dcn | P2 | — | — | — | — | — | — | — | — | 0 |
| evpn | P2 | — | — | — | — | — | — | — | — | 0 |
| irf | P2 | 1 | — | — | — | — | — | — | — | 1 |
| mpls | P2 | — | — | — | — | — | — | — | — | 0 |
| vxlan | P2 | — | — | — | — | — | — | — | — | 0 |

## Coverage Gaps (Known Support Missing Corpus)

| Feature | Vendor | Priority | Domains |
|---------|--------|----------|---------|
| acl | h3c | P0 | routing, switching, firewall |
| bgp | h3c | P0 | routing, firewall |
| bgp | huawei | P0 | routing, firewall |
| dhcp | h3c | P0 | routing, switching |
| dhcp | huawei | P0 | routing, switching |
| ipsec | h3c | P0 | routing, firewall |
| ipsec | huawei | P0 | routing, firewall |
| isis | cisco | P0 | routing |
| isis | h3c | P0 | routing |
| isis | huawei | P0 | routing |
| nat | h3c | P0 | routing, firewall |
| ospf | h3c | P0 | routing, firewall |
| prefix_list | h3c | P0 | routing |
| prefix_list | huawei | P0 | routing |
| route_policy | h3c | P0 | routing |
| route_policy | huawei | P0 | routing |
| security_policy | cisco | P0 | firewall |
| security_policy | h3c | P0 | firewall |
| static_route | h3c | P0 | routing, firewall |
| static_route | huawei | P0 | routing, firewall |
| stp | h3c | P0 | switching |
| stp | huawei | P0 | switching |
| system | cisco | P0 | routing, switching, firewall |
| system | h3c | P0 | routing, switching, firewall |
| system | huawei | P0 | routing, switching, firewall |
| vlan | h3c | P0 | switching, firewall |
| vrrp | cisco | P0 | routing, switching |
| vrrp | h3c | P0 | routing, switching |
| vrrp | huawei | P0 | routing, switching |
| aaa | cisco | P1 | routing, switching, firewall |
| aaa | h3c | P1 | routing, switching, firewall |
| aaa | huawei | P1 | routing, switching, firewall |
| bfd | cisco | P1 | routing |
| bfd | h3c | P1 | routing |
| cdp | cisco | P1 | routing, switching |
| etherchannel | cisco | P1 | switching |
| etherchannel | h3c | P1 | switching |
| etherchannel | huawei | P1 | switching |
| ipv6 | cisco | P1 | routing, switching, firewall |
| ipv6 | h3c | P1 | routing, switching, firewall |
| ipv6 | huawei | P1 | routing, switching, firewall |
| lldp | cisco | P1 | routing, switching |
| lldp | h3c | P1 | routing, switching |
| lldp | huawei | P1 | routing, switching |
| local_user | cisco | P1 | routing, switching, firewall |
| local_user | h3c | P1 | routing, switching, firewall |
| local_user | huawei | P1 | routing, switching, firewall |
| multicast | cisco | P1 | routing |
| multicast | h3c | P1 | routing |
| multicast | huawei | P1 | routing |
| ntp | cisco | P1 | routing, switching, firewall |
| ntp | h3c | P1 | routing, switching, firewall |
| ntp | huawei | P1 | routing, switching, firewall |
| pbr | cisco | P1 | routing |
| pbr | h3c | P1 | routing |
| pbr | huawei | P1 | routing |
| poe | cisco | P1 | switching |
| poe | h3c | P1 | switching |
| poe | huawei | P1 | switching |
| port_channel | cisco | P1 | routing, switching |
| port_channel | h3c | P1 | routing, switching |
| port_channel | huawei | P1 | routing, switching |
| qos | cisco | P1 | routing, switching |
| qos | h3c | P1 | routing, switching |
| qos | huawei | P1 | routing, switching |
| snmp | cisco | P1 | routing, switching, firewall |
| snmp | h3c | P1 | routing, switching, firewall |
| snmp | huawei | P1 | routing, switching, firewall |
| ssh | cisco | P1 | routing, switching, firewall |
| ssh | h3c | P1 | routing, switching, firewall |
| ssh | huawei | P1 | routing, switching, firewall |
| syslog | cisco | P1 | routing, switching, firewall |
| syslog | h3c | P1 | routing, switching, firewall |
| syslog | huawei | P1 | routing, switching, firewall |
| tunnel | h3c | P1 | routing |
| tunnel | huawei | P1 | routing |
| vrf | h3c | P1 | routing |
| vrf | huawei | P1 | routing |
| dcn | huawei | P2 | routing |
| evpn | cisco | P2 | switching |
| evpn | h3c | P2 | switching |
| evpn | huawei | P2 | switching |
| mpls | cisco | P2 | routing |
| mpls | h3c | P2 | routing |
| mpls | huawei | P2 | routing |
| vxlan | cisco | P2 | switching |
| vxlan | h3c | P2 | switching |
| vxlan | huawei | P2 | switching |

## Knowledge vs Corpus Coverage

This table shows how many features are supported per vendor in the knowledge base
vs how many have corpus test cases.

| Vendor | Knowledge Supported | Corpus Source Coverage | Corpus Target Coverage |
|--------|--------------------|----------------------|----------------------|
| Cisco | 37 | 8 | 7 |
| Huawei | 37 | 6 | 8 |
| H3c | 37 | 1 | 0 |
| Ruijie | 0 | 0 | 0 |
| Hillstone | 0 | 0 | 0 |
| Topsec | 0 | 0 | 0 |
| Dbappsecurity | 0 | 0 | 0 |
| Dptech | 0 | 0 | 0 |

## Risk Distribution

- **High**: 8 cases
- **Medium**: 5 cases
- **Low**: 2 cases

## Deployability Profile

- **Deployable**: 5 cases
- **Not deployable**: 10 cases
- **Manual review required**: 10 cases
- **No manual review**: 5 cases
