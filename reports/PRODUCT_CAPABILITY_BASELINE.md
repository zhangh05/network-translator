# Product Capability Baseline Coverage

- total: 26
- covered: 26
- missing: 0

## FIREWALL

- `firewall.objects`: auto_subset; modules: zone, address_object, service_object, object_group, object_group.member
- `firewall.policy`: auto_subset; modules: security_policy
- `firewall.nat`: manual_review; modules: firewall.nat
- `firewall.ipsec`: manual_review; modules: firewall.ipsec, interface.tunnel
- `firewall.utm_profile`: identify_only; modules: firewall.profile, time_range

## ROUTER

- `router.static_route`: auto_subset; modules: static_route, static_route.option
- `router.ospf`: auto_subset; modules: ospf.process, ospf.area, ospf.network, ospf.passive_interface, ospf.authentication, ospf.redistribute, ospf.area_special, ospf.interface_tuning
- `router.bgp`: auto_subset; modules: bgp.process, bgp.neighbor, bgp.network, bgp.password, bgp.policy, bgp.redistribute, bgp.attribute
- `router.rip`: manual_review; modules: rip.process, rip.network, rip.unknown
- `router.isis`: manual_review; modules: isis.process, isis.network, isis.unknown
- `router.vrf`: auto_subset; modules: vrf
- `router.route_policy`: manual_review; modules: route_policy, route_filter
- `router.pbr`: manual_review; modules: pbr.policy, pbr.binding
- `router.multicast`: manual_review; modules: multicast, multicast.interface
- `router.bfd`: manual_review; modules: bfd.session
- `router.dhcp`: manual_review; modules: dhcp.pool

## SWITCH

- `system.management`: auto_subset; modules: device_identity, management.ntp, management.logging, management.snmp, management.aaa
- `switch.vlan`: auto_subset; modules: vlan, interface.svi
- `switch.trunk_access`: auto_subset; modules: interface.physical, interface.lag
- `switch.lacp`: auto_subset; modules: interface.lag, interface.physical
- `switch.stp_mstp`: manual_review; modules: stp, stp.mstp
- `switch.qinq`: manual_review; modules: l2.qinq
- `switch.voice_vlan`: manual_review; modules: l2.voice_vlan
- `switch.lldp`: manual_review; modules: l2.lldp
- `switch.mac_table`: manual_review; modules: l2.mac_table
- `acl_qos`: auto_subset; modules: acl, acl_binding, qos.classifier, qos.behavior, qos.policy, qos.binding
