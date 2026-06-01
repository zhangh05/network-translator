# Product Capability Baseline Coverage

- total: 81
- covered: 81
- full: 81
- partial: 0
- missing: 0
- by_action: {"auto_subset": 11, "identify_only": 1, "manual_review": 69}

## FIREWALL

- `firewall.objects`: auto_subset; status=covered; matched=address_object, object_group, object_group.member, service_object, zone; missing=-; modules: zone, address_object, service_object, object_group, object_group.member
- `firewall.policy`: auto_subset; status=covered; matched=security_policy; missing=-; modules: security_policy
- `firewall.nat`: manual_review; status=covered; matched=firewall.nat; missing=-; modules: firewall.nat
- `firewall.ipsec`: manual_review; status=covered; matched=firewall.ipsec, interface.tunnel; missing=-; modules: firewall.ipsec, interface.tunnel
- `firewall.utm_profile`: identify_only; status=covered; matched=firewall.profile, time_range; missing=-; modules: firewall.profile, time_range
- `firewall.threat_profiles`: manual_review; status=covered; matched=firewall.application, firewall.av, firewall.ips, firewall.url_filter, firewall.user_id; missing=-; modules: firewall.ips, firewall.url_filter, firewall.av, firewall.application, firewall.user_id
- `firewall.remote_access_vpn`: manual_review; status=covered; matched=firewall.ssl_vpn; missing=-; modules: firewall.ssl_vpn
- `firewall.threat_advanced`: manual_review; status=covered; matched=firewall.dlp, firewall.dos, firewall.waf; missing=-; modules: firewall.dos, firewall.dlp, firewall.waf
- `firewall.application_delivery`: manual_review; status=covered; matched=firewall.load_balance; missing=-; modules: firewall.load_balance
- `firewall.session_logging`: manual_review; status=covered; matched=firewall.logging, firewall.session; missing=-; modules: firewall.session, firewall.logging
- `firewall.proxy_policy`: manual_review; status=covered; matched=firewall.proxy; missing=-; modules: firewall.proxy
- `firewall.dns_security`: manual_review; status=covered; matched=firewall.dns_security; missing=-; modules: firewall.dns_security
- `firewall.mail_security`: manual_review; status=covered; matched=firewall.mail_security; missing=-; modules: firewall.mail_security
- `firewall.file_blocking`: manual_review; status=covered; matched=firewall.file_blocking; missing=-; modules: firewall.file_blocking
- `firewall.sandboxing`: manual_review; status=covered; matched=firewall.sandbox; missing=-; modules: firewall.sandbox
- `firewall.ssl_decryption`: manual_review; status=covered; matched=firewall.decryption; missing=-; modules: firewall.decryption
- `firewall.high_availability`: manual_review; status=covered; matched=firewall.ha; missing=-; modules: firewall.ha
- `firewall.virtual_systems`: manual_review; status=covered; matched=firewall.vsys; missing=-; modules: firewall.vsys
- `firewall.dynamic_routing`: manual_review; status=covered; matched=firewall.routing; missing=-; modules: firewall.routing

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
- `router.dhcpv6`: manual_review; status=covered; matched=dhcpv6.pool, dhcpv6.relay, dhcpv6.relay.binding; missing=-; modules: dhcpv6.pool, dhcpv6.relay, dhcpv6.relay.binding
- `router.ipv6_first_hop_security`: manual_review; status=covered; matched=ipv6.nd_snooping, ipv6.ra_guard, ipv6.source_guard; missing=-; modules: ipv6.nd_snooping, ipv6.source_guard, ipv6.ra_guard
- `router.ipv6_interface_services`: manual_review; status=covered; matched=ipv6.interface, ipv6.nd_ra; missing=-; modules: ipv6.interface, ipv6.nd_ra
- `router.eigrp`: manual_review; status=covered; matched=eigrp; missing=-; modules: eigrp
- `router.mpls_vpn_advanced`: manual_review; status=covered; matched=mpls.l3vpn, mpls.ldp, mpls.te; missing=-; modules: mpls.ldp, mpls.te, mpls.l3vpn
- `router.bgp_advanced_families`: manual_review; status=covered; matched=bgp.evpn, bgp.flowspec, bgp.vpnv4; missing=-; modules: bgp.vpnv4, bgp.evpn, bgp.flowspec
- `router.multicast_advanced`: manual_review; status=covered; matched=multicast.igmp_tuning, multicast.msdp, multicast.rp; missing=-; modules: multicast.rp, multicast.msdp, multicast.igmp_tuning
- `router.segment_routing`: manual_review; status=covered; matched=segment_routing, segment_routing.binding; missing=-; modules: segment_routing, segment_routing.binding
- `router.ripng`: manual_review; status=covered; matched=ripng.process; missing=-; modules: ripng.process
- `router.ospf_traffic_engineering`: manual_review; status=covered; matched=ospf.te; missing=-; modules: ospf.te
- `router.bgp_confederation_rr`: manual_review; status=covered; matched=bgp.confederation, bgp.route_reflector; missing=-; modules: bgp.confederation, bgp.route_reflector
- `router.bgp_session_safety`: manual_review; status=covered; matched=bgp.gtsm, bgp.max_prefix; missing=-; modules: bgp.max_prefix, bgp.gtsm
- `router.bgp_graceful_restart`: manual_review; status=covered; matched=bgp.graceful_restart; missing=-; modules: bgp.graceful_restart
- `router.pbr_advanced`: manual_review; status=covered; matched=pbr.track, pbr.verify; missing=-; modules: pbr.track, pbr.verify
- `router.ipv6_tunnel`: manual_review; status=covered; matched=interface.tunnel6; missing=-; modules: interface.tunnel6
- `router.fhrp_tracking`: manual_review; status=covered; matched=fhrp.track; missing=-; modules: fhrp.track
- `router.acl_advanced_refs`: manual_review; status=covered; matched=acl.object_group, acl.time_range; missing=-; modules: acl.object_group, acl.time_range
- `system.ntp_authentication`: manual_review; status=covered; matched=management.ntp_auth; missing=-; modules: management.ntp_auth
- `system.programmatic_management`: manual_review; status=covered; matched=management.netconf, management.restconf; missing=-; modules: management.netconf, management.restconf
- `system.streaming_telemetry`: manual_review; status=covered; matched=management.telemetry; missing=-; modules: management.telemetry
- `system.flow_export`: manual_review; status=covered; matched=telemetry.flow; missing=-; modules: telemetry.flow
- `router.urpf`: manual_review; status=covered; matched=security.urpf; missing=-; modules: security.urpf

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
- `switch.resilience_advanced`: manual_review; status=covered; matched=l2.mlag, l2.ring_protection, l2.smart_link, lacp.tuning; missing=-; modules: l2.ring_protection, l2.smart_link, l2.mlag, lacp.tuning
- `switch.vlan_translation`: manual_review; status=covered; matched=l2.vlan_mapping; missing=-; modules: l2.vlan_mapping
- `switch.private_vlan`: manual_review; status=covered; matched=l2.private_vlan; missing=-; modules: l2.private_vlan
- `switch.registration_protocols`: manual_review; status=covered; matched=l2.gvrp, l2.mvrp; missing=-; modules: l2.gvrp, l2.mvrp
- `switch.ethernet_oam`: manual_review; status=covered; matched=oam.cfm, oam.ethernet; missing=-; modules: oam.ethernet, oam.cfm
- `switch.traffic_mirroring`: manual_review; status=covered; matched=monitor.rspan, monitor.span; missing=-; modules: monitor.span, monitor.rspan
- `switch.device_tracking`: manual_review; status=covered; matched=l2.device_tracking; missing=-; modules: l2.device_tracking
- `switch.errdisable`: manual_review; status=covered; matched=l2.errdisable; missing=-; modules: l2.errdisable
- `acl_qos`: auto_subset; status=covered; matched=acl, acl_binding, qos.behavior, qos.binding, qos.classifier, qos.policy; missing=-; modules: acl, acl_binding, qos.classifier, qos.behavior, qos.policy, qos.binding
