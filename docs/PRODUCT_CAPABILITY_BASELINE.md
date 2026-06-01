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
- SSH/Stelnet, PKI/certificate trust, advanced L2 resilience, VLAN translation, OAM/CFM, SPAN/RSPAN, device tracking, errdisable, IPv6 ND/RA/first-hop security, DHCPv6, MPLS VPN/TE, BGP VPNv4/EVPN/FlowSpec/session protection, RIPng, Segment Routing, programmatic management, telemetry/flow export, remote-access VPN, threat-prevention, firewall HA/VSYS/routing, and load-balancing profiles are surfaced as manual-review modules rather than being silently passed through.
- Missing firewall policy fields must never become implicit `any`.

## Capability Map

The machine-readable source of truth is
`core/module_graph/capability_taxonomy.py`.

| Capability | Domain | Default | Module features |
|------------|--------|---------|-----------------|
| system.management | SWITCH | auto_subset | device_identity, management.ntp, management.logging, management.snmp, management.aaa |
| system.secure_management | SWITCH | manual_review | management.ssh, management.pki |
| switch.vlan | SWITCH | auto_subset | vlan, interface.svi |
| switch.trunk_access | SWITCH | auto_subset | interface.physical, interface.lag |
| switch.lacp | SWITCH | auto_subset | interface.lag, interface.physical |
| switch.stp_mstp | SWITCH | manual_review | stp, stp.mstp |
| switch.qinq | SWITCH | manual_review | l2.qinq |
| switch.voice_vlan | SWITCH | manual_review | l2.voice_vlan |
| switch.lldp | SWITCH | manual_review | l2.lldp |
| switch.mac_table | SWITCH | manual_review | l2.mac_table |
| switch.access_security | SWITCH | manual_review | l2.dhcp_snooping, l2.source_guard, l2.arp_security, l2.port_security, l2.storm_control |
| switch.access_authentication | SWITCH | manual_review | access.auth_profile, access.dot1x, access.mac_auth, access.portal, access.radius_binding, access.interface_binding |
| switch.stack_virtualization | SWITCH | manual_review | platform.stack |
| switch.vxlan_evpn | SWITCH | manual_review | overlay.vxlan, overlay.evpn |
| switch.edge_services | SWITCH | manual_review | l2.poe, l2.loop_detection |
| switch.resilience_advanced | SWITCH | manual_review | l2.ring_protection, l2.smart_link, l2.mlag, lacp.tuning |
| switch.vlan_translation | SWITCH | manual_review | l2.vlan_mapping |
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
| router.dhcp_relay | ROUTER | manual_review | dhcp.relay, dhcp.relay.binding |
| router.dhcpv6 | ROUTER | manual_review | dhcpv6.pool, dhcpv6.relay, dhcpv6.relay.binding |
| router.ipv6_first_hop_security | ROUTER | manual_review | ipv6.nd_snooping, ipv6.source_guard, ipv6.ra_guard |
| router.ipv6_interface_services | ROUTER | manual_review | ipv6.interface, ipv6.nd_ra |
| router.eigrp | ROUTER | manual_review | eigrp |
| router.mpls_vpn_advanced | ROUTER | manual_review | mpls.ldp, mpls.te, mpls.l3vpn |
| router.bgp_advanced_families | ROUTER | manual_review | bgp.vpnv4, bgp.evpn, bgp.flowspec |
| router.multicast_advanced | ROUTER | manual_review | multicast.rp, multicast.msdp, multicast.igmp_tuning |
| router.segment_routing | ROUTER | manual_review | segment_routing, segment_routing.binding |
| firewall.objects | FIREWALL | auto_subset | zone, address_object, service_object, object_group, object_group.member |
| firewall.policy | FIREWALL | auto_subset | security_policy |
| firewall.nat | FIREWALL | manual_review | firewall.nat |
| firewall.ipsec | FIREWALL | manual_review | firewall.ipsec, interface.tunnel |
| firewall.utm_profile | FIREWALL | identify_only | firewall.profile, time_range |
| firewall.threat_profiles | FIREWALL | manual_review | firewall.ips, firewall.url_filter, firewall.av, firewall.application, firewall.user_id |
| firewall.remote_access_vpn | FIREWALL | manual_review | firewall.ssl_vpn |
| firewall.threat_advanced | FIREWALL | manual_review | firewall.dos, firewall.dlp, firewall.waf |
| firewall.application_delivery | FIREWALL | manual_review | firewall.load_balance |
| firewall.session_logging | FIREWALL | manual_review | firewall.session, firewall.logging |
| switch.private_vlan | SWITCH | manual_review | l2.private_vlan |
| switch.registration_protocols | SWITCH | manual_review | l2.gvrp, l2.mvrp |
| switch.ethernet_oam | SWITCH | manual_review | oam.ethernet, oam.cfm |
| switch.traffic_mirroring | SWITCH | manual_review | monitor.span, monitor.rspan |
| switch.device_tracking | SWITCH | manual_review | l2.device_tracking |
| switch.errdisable | SWITCH | manual_review | l2.errdisable |
| router.ripng | ROUTER | manual_review | ripng.process |
| router.ospf_traffic_engineering | ROUTER | manual_review | ospf.te |
| router.bgp_confederation_rr | ROUTER | manual_review | bgp.confederation, bgp.route_reflector |
| router.bgp_session_safety | ROUTER | manual_review | bgp.max_prefix, bgp.gtsm |
| router.bgp_graceful_restart | ROUTER | manual_review | bgp.graceful_restart |
| router.pbr_advanced | ROUTER | manual_review | pbr.track, pbr.verify |
| router.ipv6_tunnel | ROUTER | manual_review | interface.tunnel6 |
| router.fhrp_tracking | ROUTER | manual_review | fhrp.track |
| router.acl_advanced_refs | ROUTER | manual_review | acl.object_group, acl.time_range |
| system.ntp_authentication | ROUTER | manual_review | management.ntp_auth |
| system.programmatic_management | ROUTER | manual_review | management.netconf, management.restconf |
| system.streaming_telemetry | ROUTER | manual_review | management.telemetry |
| system.flow_export | ROUTER | manual_review | telemetry.flow |
| router.urpf | ROUTER | manual_review | security.urpf |
| firewall.proxy_policy | FIREWALL | manual_review | firewall.proxy |
| firewall.dns_security | FIREWALL | manual_review | firewall.dns_security |
| firewall.mail_security | FIREWALL | manual_review | firewall.mail_security |
| firewall.file_blocking | FIREWALL | manual_review | firewall.file_blocking |
| firewall.sandboxing | FIREWALL | manual_review | firewall.sandbox |
| firewall.ssl_decryption | FIREWALL | manual_review | firewall.decryption |
| firewall.high_availability | FIREWALL | manual_review | firewall.ha |
| firewall.virtual_systems | FIREWALL | manual_review | firewall.vsys |
| firewall.dynamic_routing | FIREWALL | manual_review | firewall.routing |
| acl_qos | SWITCH | auto_subset | acl, acl_binding, qos.classifier, qos.behavior, qos.policy, qos.binding |
## Current Implementation Notes

- The module graph now recognizes product-relevant L2 advanced features:
  `l2.qinq`, `l2.voice_vlan`, `l2.lldp`, `l2.mac_table`, `l2.dhcp_snooping`, `l2.source_guard`, `l2.arp_security`, `l2.port_security`, `l2.storm_control`, `l2.poe`, `l2.loop_detection`, `l2.private_vlan`, `l2.gvrp`, `l2.mvrp`, `oam.ethernet`, `oam.cfm`, `monitor.span`, `monitor.rspan`, `l2.device_tracking`, `l2.errdisable`, and `stp.mstp`.
- These features default to manual review because vendor semantics affect
  encapsulation, phone discovery, TLVs, static forwarding behavior, access security, storm control, and spanning
  tree topology.
- Routing and firewall advanced features are already split into review modules:
  RIP, RIPng, IS-IS, PBR, PBR tracking/verify, multicast, advanced multicast, BFD, DHCP, DHCPv6, DHCP Relay, IPv6 interface services, IPv6 first-hop security, IPv6 static route, OSPFv3, OSPF-TE, IPv6 ACL, EIGRP, MPLS, MPLS VPN/TE/LDP, BGP advanced address families, BGP session protection, Segment Routing, NQA/IP SLA, FHRP tracking, tunnels, uRPF, NTP auth, NETCONF/RESTCONF, telemetry, flow export, NAT, IPsec, SSL VPN, firewall threat profiles, proxy/DNS/mail/file/sandbox/decryption, HA/VSYS/routing, session/logging, load balancing, and
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
