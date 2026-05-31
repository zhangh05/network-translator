# Product Capability Baseline

This document defines the product-document aligned breadth baseline for the
module graph and fallback review layer. It is not a promise that every feature
is automatically translated. It is the minimum product map that decides whether
a source configuration block should be auto-translated, split into a
manual-review module, or identified only for audit.

## Source Alignment

The baseline is aligned to public vendor product/configuration documentation:

- Cisco IOS XE configuration guide families include LAN Switching, QoS, Security,
  and IP Routing guides.
- Huawei VRP Ethernet Switching documentation covers link aggregation, VLAN,
  Voice VLAN, VLAN mapping, QinQ, GVRP, MAC table, STP/RSTP/MSTP, SEP, and
  related switching services.
- H3C Comware configuration guides are organized around Layer 2 LAN Switching,
  Layer 3/IP Routing, ACL and QoS, multicast, security, AAA/PKI/SSH, and attack
  protection.
- Ruijie RGOS configuration guides include static routing, RIP/RIPng, OSPFv2/v3,
  IS-IS, BGP, VRF, routing policies, PBR, multicast, MPLS, ACL, and QoS.
- Huawei USG, Hillstone StoneOS, Topsec, and DPtech firewall product material
  covers zones, objects, security policies, NAT, IPsec/VPN, URL/AV/IPS,
  application/user profiles, session handling, and audit logging.

## Baseline Rules

- `auto_subset`: only a conservative subset may become deployable configuration.
  Anything outside the explicit subset remains manual review.
- `manual_review`: the module must be identified and surfaced with source
  evidence, but must not be silently auto-translated.
- `identify_only`: the feature is product-relevant, but current safe behavior is
  recognition, evidence, and manual-review reporting.
- Secrets, keys, communities, and authentication material are always redacted.
- Missing firewall policy fields must never become implicit `any`.

## Capability Map

The machine-readable source of truth is
`core/module_graph/capability_taxonomy.py`.

| Capability | Domain | Default | Module features |
|------------|--------|---------|-----------------|
| system.management | SWITCH | auto_subset | device_identity, management.ntp, management.logging, management.snmp, management.aaa |
| switch.vlan | SWITCH | auto_subset | vlan, interface.svi |
| switch.trunk_access | SWITCH | auto_subset | interface.physical, interface.lag |
| switch.lacp | SWITCH | auto_subset | interface.lag, interface.physical |
| switch.stp_mstp | SWITCH | manual_review | stp, stp.mstp |
| switch.qinq | SWITCH | manual_review | l2.qinq |
| switch.voice_vlan | SWITCH | manual_review | l2.voice_vlan |
| switch.lldp | SWITCH | manual_review | l2.lldp |
| switch.mac_table | SWITCH | manual_review | l2.mac_table |
| switch.access_security | SWITCH | manual_review | l2.dhcp_snooping, l2.source_guard, l2.arp_security, l2.port_security, l2.storm_control |
| switch.stack_virtualization | SWITCH | manual_review | platform.stack |
| switch.vxlan_evpn | SWITCH | manual_review | overlay.vxlan, overlay.evpn |
| switch.edge_services | SWITCH | manual_review | l2.poe, l2.loop_detection |
| router.static_route | ROUTER | auto_subset | static_route, static_route.option |
| router.ospf | ROUTER | auto_subset | ospf.process, ospf.area, ospf.network, ospf.passive_interface, ospf.authentication, ospf.redistribute, ospf.area_special, ospf.interface_tuning |
| router.bgp | ROUTER | auto_subset | bgp.process, bgp.neighbor, bgp.network, bgp.password, bgp.policy, bgp.redistribute, bgp.attribute |
| router.rip | ROUTER | manual_review | rip.process, rip.network, rip.unknown |
| router.isis | ROUTER | manual_review | isis.process, isis.network_entity, isis.interface_tuning, isis.redistribute |
| router.vrf | ROUTER | auto_subset | vrf |
| router.route_policy | ROUTER | manual_review | route_policy, route_filter |
| router.pbr | ROUTER | manual_review | pbr.policy, pbr.binding |
| router.multicast | ROUTER | manual_review | multicast, multicast.interface |
| router.bfd | ROUTER | manual_review | bfd.session |
| router.dhcp | ROUTER | manual_review | dhcp.pool |
| router.mpls | ROUTER | manual_review | mpls |
| router.nqa_ip_sla | ROUTER | manual_review | nqa, ip_sla |
| router.fhrp | ROUTER | manual_review | fhrp.vrrp, fhrp.hsrp |
| router.tunnel | ROUTER | manual_review | interface.tunnel |
| router.ipv6_routing | ROUTER | manual_review | ipv6.static_route, ospfv3.process, ipv6.acl |
| router.dhcp_relay | ROUTER | manual_review | dhcp.relay |
| router.eigrp | ROUTER | manual_review | eigrp |
| firewall.objects | FIREWALL | auto_subset | zone, address_object, service_object, object_group, object_group.member |
| firewall.policy | FIREWALL | auto_subset | security_policy |
| firewall.nat | FIREWALL | manual_review | firewall.nat |
| firewall.ipsec | FIREWALL | manual_review | firewall.ipsec, interface.tunnel |
| firewall.utm_profile | FIREWALL | identify_only | firewall.profile, time_range |
| firewall.session_logging | FIREWALL | manual_review | firewall.session, firewall.logging |
| acl_qos | SWITCH | auto_subset | acl, acl_binding, qos.classifier, qos.behavior, qos.policy, qos.binding |

## Current Implementation Notes

- The module graph now recognizes product-relevant L2 advanced features:
  `l2.qinq`, `l2.voice_vlan`, `l2.lldp`, `l2.mac_table`, `l2.dhcp_snooping`, `l2.source_guard`, `l2.arp_security`, `l2.port_security`, `l2.storm_control`, `l2.poe`, `l2.loop_detection`, and `stp.mstp`.
- These features default to manual review because vendor semantics affect
  encapsulation, phone discovery, TLVs, static forwarding behavior, access security, storm control, and spanning
  tree topology.
- Routing and firewall advanced features are already split into review modules:
  RIP, IS-IS, PBR, multicast, BFD, DHCP, DHCP Relay, IPv6 static route, OSPFv3, IPv6 ACL, EIGRP, MPLS, NQA/IP SLA, FHRP, tunnels, NAT, IPsec, firewall profiles, session/logging, and
  time ranges.
- The UI and exported risk report use module graph evidence to show original
  source snippets, reason, action, group, priority, and coupling relations.

## Coverage Report

Run:

```bash
PYTHONPATH=. venv/bin/python3 scripts/report_product_capability_baseline.py
```

Outputs:

- `reports/product_capability_baseline.json`
- `reports/PRODUCT_CAPABILITY_BASELINE.md`

The report is intentionally breadth-oriented. It confirms that the project has a
named module feature for every product-baseline capability; it does not claim
full semantic equivalence.

The JSON and Markdown reports are generated from probe configurations that run
through `build_module_graph()`. Each capability includes:

- `observed_features`: module features actually produced by the probe config.
- `matched_features`: baseline module features observed in the probe output.
- `missing_module_features`: baseline module features not observed by the probe.
- `coverage_status`: `covered`, `partial`, or `missing`.

`covered` means at least one auditable module exists for that product capability.
`partial` means the capability is visible but not all listed subfeatures are
covered by the current probe. It must not be interpreted as production-grade
semantic equivalence.
