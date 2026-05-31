# Product Capability Baseline Coverage

- total: 26
- covered: 26
- full: 26
- partial: 0
- missing: 0
- by_action: {"auto_subset": 11, "identify_only": 1, "manual_review": 14}

## FIREWALL

- `firewall.objects`: auto_subset; status=covered; matched=address_object, object_group, object_group.member, service_object, zone; missing=-; modules: zone, address_object, service_object, object_group, object_group.member
- `firewall.policy`: auto_subset; status=covered; matched=security_policy; missing=-; modules: security_policy
- `firewall.nat`: manual_review; status=covered; matched=firewall.nat; missing=-; modules: firewall.nat
- `firewall.ipsec`: manual_review; status=covered; matched=firewall.ipsec, interface.tunnel; missing=-; modules: firewall.ipsec, interface.tunnel
- `firewall.utm_profile`: identify_only; status=covered; matched=firewall.profile, time_range; missing=-; modules: firewall.profile, time_range

## ROUTER

- `router.static_route`: auto_subset; status=covered; matched=static_route, static_route.option; missing=-; modules: static_route, static_route.option
- `router.ospf`: auto_subset; status=covered; matched=ospf.area, ospf.area_special, ospf.authentication, ospf.interface_tuning, ospf.network, ospf.passive_interface, ospf.process, ospf.redistribute; missing=-; modules: ospf.process, ospf.area, ospf.network, ospf.passive_interface, ospf.authentication, ospf.redistribute, ospf.area_special, ospf.interface_tuning
- `router.bgp`: auto_subset; status=covered; matched=bgp.attribute, bgp.neighbor, bgp.network, bgp.password, bgp.policy, bgp.process, bgp.redistribute; missing=-; modules: bgp.process, bgp.neighbor, bgp.network, bgp.password, bgp.policy, bgp.redistribute, bgp.attribute
- `router.rip`: manual_review; status=covered; matched=rip.network, rip.process, rip.unknown; missing=-; modules: rip.process, rip.network, rip.unknown
- `router.isis`: manual_review; status=covered; matched=isis.interface_tuning, isis.network_entity, isis.process, isis.redistribute; missing=-; modules: isis.process, isis.network_entity, isis.interface_tuning, isis.redistribute
- `router.vrf`: auto_subset; status=covered; matched=vrf; missing=-; modules: vrf
- `router.route_policy`: manual_review; status=covered; matched=route_filter, route_policy; missing=-; modules: route_policy, route_filter
- `router.pbr`: manual_review; status=covered; matched=pbr.binding, pbr.policy; missing=-; modules: pbr.policy, pbr.binding
- `router.multicast`: manual_review; status=covered; matched=multicast, multicast.interface; missing=-; modules: multicast, multicast.interface
- `router.bfd`: manual_review; status=covered; matched=bfd.session; missing=-; modules: bfd.session
- `router.dhcp`: manual_review; status=covered; matched=dhcp.pool; missing=-; modules: dhcp.pool

## SWITCH

- `system.management`: auto_subset; status=covered; matched=device_identity, management.aaa, management.logging, management.ntp, management.snmp; missing=-; modules: device_identity, management.ntp, management.logging, management.snmp, management.aaa
- `switch.vlan`: auto_subset; status=covered; matched=interface.svi, vlan; missing=-; modules: vlan, interface.svi
- `switch.trunk_access`: auto_subset; status=covered; matched=interface.lag, interface.physical; missing=-; modules: interface.physical, interface.lag
- `switch.lacp`: auto_subset; status=covered; matched=interface.lag, interface.physical; missing=-; modules: interface.lag, interface.physical
- `switch.stp_mstp`: manual_review; status=covered; matched=stp, stp.mstp; missing=-; modules: stp, stp.mstp
- `switch.qinq`: manual_review; status=covered; matched=l2.qinq; missing=-; modules: l2.qinq
- `switch.voice_vlan`: manual_review; status=covered; matched=l2.voice_vlan; missing=-; modules: l2.voice_vlan
- `switch.lldp`: manual_review; status=covered; matched=l2.lldp; missing=-; modules: l2.lldp
- `switch.mac_table`: manual_review; status=covered; matched=l2.mac_table; missing=-; modules: l2.mac_table
- `acl_qos`: auto_subset; status=covered; matched=acl, acl_binding, qos.behavior, qos.binding, qos.classifier, qos.policy; missing=-; modules: acl, acl_binding, qos.classifier, qos.behavior, qos.policy, qos.binding
