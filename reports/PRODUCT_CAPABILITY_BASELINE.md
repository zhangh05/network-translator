# Product Capability Baseline Coverage

- total: 41
- covered: 41
- full: 41
- partial: 0
- missing: 0
- by_action: {"auto_subset": 11, "identify_only": 1, "manual_review": 29}

## FIREWALL

- `firewall.objects`: auto_subset; status=covered; matched=address_object, object_group, object_group.member, service_object, zone; missing=-; modules: zone, address_object, service_object, object_group, object_group.member
- `firewall.policy`: auto_subset; status=covered; matched=security_policy; missing=-; modules: security_policy
- `firewall.nat`: manual_review; status=covered; matched=firewall.nat; missing=-; modules: firewall.nat
- `firewall.ipsec`: manual_review; status=covered; matched=firewall.ipsec, interface.tunnel; missing=-; modules: firewall.ipsec, interface.tunnel
- `firewall.utm_profile`: identify_only; status=covered; matched=firewall.profile, time_range; missing=-; modules: firewall.profile, time_range
- `firewall.threat_profiles`: manual_review; status=covered; matched=firewall.application, firewall.av, firewall.ips, firewall.url_filter, firewall.user_id; missing=-; modules: firewall.ips, firewall.url_filter, firewall.av, firewall.application, firewall.user_id
- `firewall.session_logging`: manual_review; status=covered; matched=firewall.logging, firewall.session; missing=-; modules: firewall.session, firewall.logging

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
- `router.mpls`: manual_review; status=covered; matched=mpls; missing=-; modules: mpls
- `router.nqa_ip_sla`: manual_review; status=covered; matched=ip_sla, nqa; missing=-; modules: nqa, ip_sla
- `router.fhrp`: manual_review; status=covered; matched=fhrp.hsrp, fhrp.vrrp; missing=-; modules: fhrp.vrrp, fhrp.hsrp
- `router.tunnel`: manual_review; status=covered; matched=interface.tunnel; missing=-; modules: interface.tunnel
- `router.ipv6_routing`: manual_review; status=covered; matched=ipv6.acl, ipv6.static_route, ospfv3.process; missing=-; modules: ipv6.static_route, ospfv3.process, ipv6.acl
- `router.dhcp_relay`: manual_review; status=covered; matched=dhcp.relay, dhcp.relay.binding; missing=-; modules: dhcp.relay, dhcp.relay.binding
- `router.ipv6_interface_services`: manual_review; status=covered; matched=ipv6.interface, ipv6.nd_ra; missing=-; modules: ipv6.interface, ipv6.nd_ra
- `router.eigrp`: manual_review; status=covered; matched=eigrp; missing=-; modules: eigrp

## SWITCH

- `system.management`: auto_subset; status=covered; matched=device_identity, management.aaa, management.logging, management.ntp, management.snmp; missing=-; modules: device_identity, management.ntp, management.logging, management.snmp, management.aaa
- `system.secure_management`: manual_review; status=covered; matched=management.pki, management.ssh; missing=-; modules: management.ssh, management.pki
- `switch.vlan`: auto_subset; status=covered; matched=interface.svi, vlan; missing=-; modules: vlan, interface.svi
- `switch.trunk_access`: auto_subset; status=covered; matched=interface.lag, interface.physical; missing=-; modules: interface.physical, interface.lag
- `switch.lacp`: auto_subset; status=covered; matched=interface.lag, interface.physical; missing=-; modules: interface.lag, interface.physical
- `switch.stp_mstp`: manual_review; status=covered; matched=stp, stp.mstp; missing=-; modules: stp, stp.mstp
- `switch.qinq`: manual_review; status=covered; matched=l2.qinq; missing=-; modules: l2.qinq
- `switch.voice_vlan`: manual_review; status=covered; matched=l2.voice_vlan; missing=-; modules: l2.voice_vlan
- `switch.lldp`: manual_review; status=covered; matched=l2.lldp; missing=-; modules: l2.lldp
- `switch.mac_table`: manual_review; status=covered; matched=l2.mac_table; missing=-; modules: l2.mac_table
- `switch.access_security`: manual_review; status=covered; matched=l2.arp_security, l2.dhcp_snooping, l2.port_security, l2.source_guard, l2.storm_control; missing=-; modules: l2.dhcp_snooping, l2.source_guard, l2.arp_security, l2.port_security, l2.storm_control
- `switch.stack_virtualization`: manual_review; status=covered; matched=platform.stack; missing=-; modules: platform.stack
- `switch.vxlan_evpn`: manual_review; status=covered; matched=overlay.evpn, overlay.vxlan; missing=-; modules: overlay.vxlan, overlay.evpn
- `switch.edge_services`: manual_review; status=covered; matched=l2.loop_detection, l2.poe; missing=-; modules: l2.poe, l2.loop_detection
- `acl_qos`: auto_subset; status=covered; matched=acl, acl_binding, qos.behavior, qos.binding, qos.classifier, qos.policy; missing=-; modules: acl, acl_binding, qos.classifier, qos.behavior, qos.policy, qos.binding
