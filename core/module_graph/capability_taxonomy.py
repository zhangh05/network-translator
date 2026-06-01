from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class CapabilitySpec:
    """Product-document aligned capability breadth item."""

    capability_id: str
    domain: str
    product_area: str
    module_features: tuple[str, ...]
    default_action: str
    vendor_platforms: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


SWITCH_PLATFORMS = ("cisco_ios_xe", "h3c_comware", "huawei_vrp", "ruijie_rgos")
ROUTER_PLATFORMS = ("cisco_ios_xe", "h3c_comware", "huawei_vrp", "ruijie_rgos")
FIREWALL_PLATFORMS = ("huawei_usg", "hillstone_stoneos", "topsec_tos", "dptech_fw")


PRODUCT_CAPABILITY_BASELINE: tuple[CapabilitySpec, ...] = (
    CapabilitySpec(
        "system.management",
        "SWITCH",
        "Basic configuration and management",
        ("device_identity", "management.ntp", "management.logging", "management.snmp", "management.aaa"),
        "auto_subset",
        SWITCH_PLATFORMS + ROUTER_PLATFORMS,
        ("Cisco IOS XE configuration guides", "H3C configuration guides", "Huawei VRP configuration guides", "Ruijie RGOS configuration guide"),
        "Secrets and AAA policies remain manual review.",
    ),
    CapabilitySpec(
        "system.secure_management",
        "SWITCH",
        "Secure management access",
        ("management.ssh", "management.pki"),
        "manual_review",
        SWITCH_PLATFORMS + ROUTER_PLATFORMS + FIREWALL_PLATFORMS,
        ("Cisco IOS XE Security Configuration Guide", "Huawei PKI and SSH Configuration Guide", "H3C PKI/SSH Configuration Guide", "Firewall secure management documentation"),
        "SSH/Stelnet and PKI/certificate material are recognized and reviewed; secrets remain redacted.",
    ),
    CapabilitySpec(
        "switch.vlan",
        "SWITCH",
        "Ethernet switching",
        ("vlan", "interface.svi"),
        "auto_subset",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "Cisco LAN Switching Configuration Guide", "H3C Layer 2 LAN Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
    ),
    CapabilitySpec(
        "switch.trunk_access",
        "SWITCH",
        "Ethernet switching",
        ("interface.physical", "interface.lag"),
        "auto_subset",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "Cisco LAN Switching Configuration Guide", "H3C Layer 2 LAN Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
    ),
    CapabilitySpec(
        "switch.lacp",
        "SWITCH",
        "Link aggregation",
        ("interface.lag", "interface.physical"),
        "auto_subset",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "H3C Layer 2 LAN Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
        "Member binding is tracked as module coupling.",
    ),
    CapabilitySpec(
        "switch.stp_mstp",
        "SWITCH",
        "STP/RSTP/MSTP",
        ("stp", "stp.mstp"),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "Cisco LAN Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
        "Edge-port subset can translate; MST regions and instance mapping require review.",
    ),
    CapabilitySpec(
        "switch.qinq",
        "SWITCH",
        "QinQ / VLAN mapping",
        ("l2.qinq",),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
    ),
    CapabilitySpec(
        "switch.voice_vlan",
        "SWITCH",
        "Voice VLAN",
        ("l2.voice_vlan",),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
    ),
    CapabilitySpec(
        "switch.lldp",
        "SWITCH",
        "Neighbor discovery",
        ("l2.lldp",),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Ruijie Ethernet Switching Configuration", "Cisco LAN Switching Configuration Guide", "Huawei Ethernet Switching Configuration Guide"),
    ),
    CapabilitySpec(
        "switch.mac_table",
        "SWITCH",
        "MAC table",
        ("l2.mac_table",),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
    ),
    CapabilitySpec(
        "switch.access_security",
        "SWITCH",
        "Access security",
        ("l2.dhcp_snooping", "l2.source_guard", "l2.arp_security", "l2.port_security", "l2.storm_control"),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Cisco LAN Switching Security Configuration Guide", "Huawei Ethernet Switching Security Configuration", "H3C Security Configuration Guide", "Ruijie Security Configuration"),
        "DHCP snooping, ARP inspection, source guard, port security, and storm control are recognized but require review.",
    ),
    CapabilitySpec(
        "switch.access_authentication",
        "SWITCH",
        "Access authentication / NAC",
        ("access.auth_profile", "access.dot1x", "access.mac_auth", "access.portal", "access.radius_binding", "access.interface_binding"),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Cisco IOS XE 802.1X Configuration Guide", "Huawei NAC Configuration Guide", "H3C Access Authentication Configuration Guide", "Ruijie 802.1X/MAB Configuration Guide"),
        "802.1X, MAC authentication, Portal, RADIUS domain binding, and interface authorization behavior are recognized as coupled manual-review modules.",
    ),
    CapabilitySpec(
        "switch.stack_virtualization",
        "SWITCH",
        "Stacking / chassis virtualization",
        ("platform.stack",),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Cisco StackWise/VSS configuration guides", "H3C IRF configuration guides", "Huawei CSS/iStack documentation", "Ruijie VSF/VSU documentation"),
    ),
    CapabilitySpec(
        "switch.vxlan_evpn",
        "SWITCH",
        "VXLAN / EVPN overlay",
        ("overlay.vxlan", "overlay.evpn"),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Cisco VXLAN EVPN configuration guides", "Huawei VXLAN configuration guides", "H3C VXLAN configuration guides", "Ruijie VXLAN EVPN documentation"),
    ),
    CapabilitySpec(
        "switch.edge_services",
        "SWITCH",
        "Edge services",
        ("l2.poe", "l2.loop_detection"),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Cisco PoE and UDLD/loop detection guides", "Huawei PoE and loop detection documentation", "H3C PoE and loopback detection guides", "Ruijie PoE and loop prevention documentation"),
    ),
    CapabilitySpec(
        "switch.resilience_advanced",
        "SWITCH",
        "Advanced L2 resilience",
        ("l2.ring_protection", "l2.smart_link", "l2.mlag", "lacp.tuning"),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Huawei ERPS/Smart Link/M-LAG documentation", "H3C RRPP/IRF/LACP documentation", "Cisco vPC/LACP documentation", "Ruijie ring protection documentation"),
    ),
    CapabilitySpec(
        "switch.vlan_translation",
        "SWITCH",
        "VLAN translation / mapping",
        ("l2.vlan_mapping",),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Huawei VLAN mapping documentation", "H3C VLAN mapping documentation", "Ruijie VLAN translation documentation", "Cisco VLAN translation documentation"),
    ),
    CapabilitySpec(
        "router.static_route",
        "ROUTER",
        "IP routing",
        ("static_route", "static_route.option"),
        "auto_subset",
        ROUTER_PLATFORMS,
        ("Cisco IOS XE IP Routing Configuration Guide", "H3C Layer 3 IP Routing Configuration Guide", "Huawei VRP IP Routing Configuration", "Ruijie IP Routing Configuration"),
    ),
    CapabilitySpec(
        "router.ospf",
        "ROUTER",
        "IP routing",
        ("ospf.process", "ospf.area", "ospf.network", "ospf.passive_interface", "ospf.authentication", "ospf.redistribute", "ospf.area_special", "ospf.interface_tuning"),
        "auto_subset",
        ROUTER_PLATFORMS,
        ("Cisco IOS XE IP Routing Configuration Guide", "Huawei VRP IP Routing Configuration", "Ruijie IP Routing Configuration"),
    ),
    CapabilitySpec(
        "router.bgp",
        "ROUTER",
        "IP routing",
        ("bgp.process", "bgp.neighbor", "bgp.network", "bgp.password", "bgp.policy", "bgp.redistribute", "bgp.attribute"),
        "auto_subset",
        ROUTER_PLATFORMS,
        ("Cisco IOS XE IP Routing Configuration Guide", "Huawei VRP IP Routing Configuration", "Ruijie IP Routing Configuration"),
    ),
    CapabilitySpec(
        "router.rip",
        "ROUTER",
        "IP routing",
        ("rip.process", "rip.network", "rip.unknown"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("H3C Layer 3 IP Routing Configuration Guide", "Ruijie IP Routing Configuration"),
    ),
    CapabilitySpec(
        "router.isis",
        "ROUTER",
        "IP routing",
        ("isis.process", "isis.network_entity", "isis.interface_tuning", "isis.redistribute"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Huawei VRP IP Routing Configuration", "Ruijie IP Routing Configuration"),
    ),
    CapabilitySpec(
        "router.vrf",
        "ROUTER",
        "VPN/VRF",
        ("vrf",),
        "auto_subset",
        ROUTER_PLATFORMS,
        ("Cisco IOS XE IP Routing Configuration Guide", "Huawei VRP IP Routing Configuration", "Ruijie IP Routing Configuration"),
    ),
    CapabilitySpec(
        "router.route_policy",
        "ROUTER",
        "Routing policies",
        ("route_policy", "route_filter"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Ruijie IP Routing Configuration", "H3C ACL and QoS Configuration Guide", "Cisco IOS XE IP Routing Configuration Guide"),
    ),
    CapabilitySpec(
        "router.pbr",
        "ROUTER",
        "Policy-based routing",
        ("pbr.policy", "pbr.binding"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Ruijie IP Routing Configuration", "Cisco IOS XE IP Routing Configuration Guide"),
    ),
    CapabilitySpec(
        "router.multicast",
        "ROUTER",
        "Multicast",
        ("multicast", "multicast.interface"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Ruijie Multicast Configuration", "H3C IP Multicast Configuration Guide"),
    ),
    CapabilitySpec(
        "router.bfd",
        "ROUTER",
        "Resilience",
        ("bfd.session",),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Ruijie Device Management Configuration", "Huawei VRP Reliability Configuration"),
    ),
    CapabilitySpec(
        "router.dhcp",
        "ROUTER",
        "IP services",
        ("dhcp.pool",),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Ruijie Device Management Configuration", "Cisco IOS XE IP Addressing Services"),
    ),
    CapabilitySpec(
        "router.mpls",
        "ROUTER",
        "MPLS / label switching",
        ("mpls",),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Cisco MPLS Configuration Guide", "Huawei MPLS Configuration Guide", "H3C MPLS Configuration Guide", "Ruijie MPLS Configuration"),
    ),
    CapabilitySpec(
        "router.nqa_ip_sla",
        "ROUTER",
        "NQA / IP SLA",
        ("nqa", "ip_sla"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Huawei NQA Configuration Guide", "Cisco IP SLA Configuration Guide", "H3C NQA Configuration Guide", "Ruijie Device Management Configuration"),
    ),
    CapabilitySpec(
        "router.fhrp",
        "ROUTER",
        "First-hop redundancy",
        ("fhrp.vrrp", "fhrp.hsrp"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Cisco HSRP Configuration Guide", "Huawei VRRP Configuration Guide", "H3C VRRP Configuration Guide", "Ruijie VRRP Configuration"),
    ),
    CapabilitySpec(
        "router.tunnel",
        "ROUTER",
        "Tunnel interfaces",
        ("interface.tunnel",),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Cisco Tunnel Interface Configuration Guide", "Huawei GRE/IPsec tunnel documentation", "H3C Tunnel Configuration Guide", "Ruijie Tunnel Configuration"),
    ),
    CapabilitySpec(
        "router.ipv6_routing",
        "ROUTER",
        "IPv6 routing and filtering",
        ("ipv6.static_route", "ospfv3.process", "ipv6.acl"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Cisco IPv6 Routing Configuration Guide", "Huawei IPv6 Configuration Guide", "H3C IPv6 Configuration Guide", "Ruijie IPv6 Configuration"),
    ),
    CapabilitySpec(
        "router.dhcp_relay",
        "ROUTER",
        "DHCP relay",
        ("dhcp.relay", "dhcp.relay.binding"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Cisco DHCP Relay Configuration Guide", "Huawei DHCP Relay Configuration Guide", "H3C DHCP Relay Configuration Guide", "Ruijie DHCP Configuration"),
    ),
    CapabilitySpec(
        "router.dhcpv6",
        "ROUTER",
        "DHCPv6 services",
        ("dhcpv6.pool", "dhcpv6.relay", "dhcpv6.relay.binding"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Cisco DHCPv6 Configuration Guide", "Huawei DHCPv6 Configuration Guide", "H3C DHCPv6 Configuration Guide", "Ruijie IPv6 services documentation"),
    ),
    CapabilitySpec(
        "router.ipv6_first_hop_security",
        "ROUTER",
        "IPv6 first-hop security",
        ("ipv6.nd_snooping", "ipv6.source_guard", "ipv6.ra_guard"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Cisco IPv6 First Hop Security", "Huawei IPv6 security documentation", "H3C IPv6 ND/RA security documentation", "Ruijie IPv6 security documentation"),
    ),
    CapabilitySpec(
        "router.ipv6_interface_services",
        "ROUTER",
        "IPv6 interface services",
        ("ipv6.interface", "ipv6.nd_ra"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Cisco IPv6 First Hop Security and ND documentation", "Huawei IPv6 ND/RA Configuration Guide", "H3C IPv6 Basics Configuration Guide", "Ruijie IPv6 Configuration"),
        "Interface IPv6 address, ND, RA, and host autoconfiguration behavior must be reviewed per platform.",
    ),
    CapabilitySpec(
        "router.eigrp",
        "ROUTER",
        "Cisco-specific EIGRP",
        ("eigrp",),
        "manual_review",
        ("cisco_ios_xe",),
        ("Cisco EIGRP Configuration Guide",),
        "Cisco-specific routing protocol; non-Cisco migration requires redesign or explicit review.",
    ),
    CapabilitySpec(
        "router.mpls_vpn_advanced",
        "ROUTER",
        "Advanced MPLS / L3VPN",
        ("mpls.ldp", "mpls.te", "mpls.l3vpn"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Cisco MPLS L3VPN/TE documentation", "Huawei MPLS VPN documentation", "H3C MPLS VPN documentation", "Ruijie MPLS documentation"),
    ),
    CapabilitySpec(
        "router.bgp_advanced_families",
        "ROUTER",
        "BGP advanced address families",
        ("bgp.vpnv4", "bgp.evpn", "bgp.flowspec"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Cisco BGP VPNv4/EVPN/FlowSpec documentation", "Huawei BGP VPNv4/EVPN documentation", "H3C BGP VPN documentation", "Ruijie BGP documentation"),
    ),
    CapabilitySpec(
        "router.multicast_advanced",
        "ROUTER",
        "Advanced multicast",
        ("multicast.rp", "multicast.msdp", "multicast.igmp_tuning"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Cisco Multicast Configuration Guide", "Huawei Multicast Configuration Guide", "H3C Multicast Configuration Guide", "Ruijie Multicast Configuration"),
    ),
    CapabilitySpec(
        "router.segment_routing",
        "ROUTER",
        "Segment Routing",
        ("segment_routing", "segment_routing.binding"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Cisco Segment Routing Configuration Guide", "Huawei Segment Routing documentation", "H3C Segment Routing documentation", "Ruijie SR documentation"),
    ),
    CapabilitySpec(
        "firewall.objects",
        "FIREWALL",
        "Objects",
        ("zone", "address_object", "service_object", "object_group", "object_group.member"),
        "auto_subset",
        FIREWALL_PLATFORMS,
        ("Huawei USG Quick Configuration Guide", "Hillstone StoneOS User Manual", "DPtech Firewall Technical White Paper"),
    ),
    CapabilitySpec(
        "firewall.policy",
        "FIREWALL",
        "Security policy",
        ("security_policy",),
        "auto_subset",
        FIREWALL_PLATFORMS,
        ("Huawei USG Quick Configuration Guide", "Hillstone StoneOS User Manual", "DPtech Firewall Technical White Paper", "Topsec Firewall product documentation"),
    ),
    CapabilitySpec(
        "firewall.nat",
        "FIREWALL",
        "NAT",
        ("firewall.nat",),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Huawei USG Quick Configuration Guide", "DPtech Firewall Technical White Paper", "Hillstone StoneOS User Manual"),
    ),
    CapabilitySpec(
        "firewall.ipsec",
        "FIREWALL",
        "IPsec / VPN",
        ("firewall.ipsec", "interface.tunnel"),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Huawei USG VPN Guide", "Hillstone StoneOS User Manual", "DPtech VPN Security Gateway Technical White Paper"),
    ),
    CapabilitySpec(
        "firewall.utm_profile",
        "FIREWALL",
        "UTM / application security",
        ("firewall.profile", "time_range"),
        "identify_only",
        FIREWALL_PLATFORMS,
        ("DPtech Firewall Technical White Paper", "Hillstone StoneOS product guide", "Huawei USG support guide"),
    ),
    CapabilitySpec(
        "firewall.threat_profiles",
        "FIREWALL",
        "Threat prevention profiles",
        ("firewall.ips", "firewall.url_filter", "firewall.av", "firewall.application", "firewall.user_id"),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Huawei USG security profile documentation", "Hillstone StoneOS security profile documentation", "Topsec threat prevention documentation", "DPtech security profile documentation"),
        "Threat profile semantics depend on signature databases, user identity sources, application libraries, and action defaults.",
    ),
    CapabilitySpec(
        "firewall.remote_access_vpn",
        "FIREWALL",
        "Remote access VPN",
        ("firewall.ssl_vpn",),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Huawei USG SSL VPN documentation", "Hillstone SSL VPN documentation", "Topsec remote access VPN documentation", "DPtech VPN documentation"),
    ),
    CapabilitySpec(
        "firewall.threat_advanced",
        "FIREWALL",
        "Advanced threat prevention",
        ("firewall.dos", "firewall.dlp", "firewall.waf"),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Huawei USG threat defense documentation", "Hillstone security profile documentation", "Topsec threat prevention documentation", "DPtech security profile documentation"),
    ),
    CapabilitySpec(
        "firewall.application_delivery",
        "FIREWALL",
        "Application delivery / load balancing",
        ("firewall.load_balance",),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Huawei USG server load balancing documentation", "Hillstone StoneOS SLB documentation", "Topsec application delivery documentation", "DPtech load balancing documentation"),
    ),
    CapabilitySpec(
        "firewall.session_logging",
        "FIREWALL",
        "Session and audit logging",
        ("firewall.session", "firewall.logging"),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Huawei USG logging/session guides", "Hillstone StoneOS logging/session documentation", "Topsec firewall audit documentation", "DPtech firewall logging documentation"),
    ),
    CapabilitySpec(
        "switch.private_vlan",
        "SWITCH",
        "Private VLAN / isolated L2 domains",
        ("l2.private_vlan",),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Cisco Private VLAN documentation", "Huawei PVLAN documentation", "H3C PVLAN documentation", "Ruijie PVLAN documentation"),
        "PVLAN primary/secondary/promiscuous mapping must be reviewed per target platform.",
    ),
    CapabilitySpec(
        "switch.registration_protocols",
        "SWITCH",
        "Dynamic VLAN registration",
        ("l2.gvrp", "l2.mvrp"),
        "manual_review",
        SWITCH_PLATFORMS,
        ("GVRP/MVRP product documentation",),
        "Dynamic VLAN registration changes VLAN propagation boundaries and should not be silently converted.",
    ),
    CapabilitySpec(
        "switch.ethernet_oam",
        "SWITCH",
        "Ethernet OAM / CFM",
        ("oam.ethernet", "oam.cfm"),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Ethernet OAM and CFM configuration guides",),
        "OAM/CFM maintenance domains, levels, and actions require review.",
    ),
    CapabilitySpec(
        "switch.traffic_mirroring",
        "SWITCH",
        "SPAN / RSPAN traffic mirroring",
        ("monitor.span", "monitor.rspan"),
        "manual_review",
        SWITCH_PLATFORMS,
        ("SPAN/RSPAN/port mirroring configuration guides",),
        "Mirror directions, remote VLANs, and destination ports are target-specific.",
    ),
    CapabilitySpec(
        "switch.device_tracking",
        "SWITCH",
        "Endpoint device tracking",
        ("l2.device_tracking",),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Device tracking / endpoint detection documentation",),
    ),
    CapabilitySpec(
        "switch.errdisable",
        "SWITCH",
        "Errdisable recovery",
        ("l2.errdisable",),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Errdisable and fault recovery documentation",),
    ),
    CapabilitySpec(
        "router.ripng",
        "ROUTER",
        "RIPng IPv6 routing",
        ("ripng.process",),
        "manual_review",
        ROUTER_PLATFORMS,
        ("IPv6 routing and RIPng configuration guides",),
    ),
    CapabilitySpec(
        "router.ospf_traffic_engineering",
        "ROUTER",
        "OSPF traffic engineering",
        ("ospf.te",),
        "manual_review",
        ROUTER_PLATFORMS,
        ("OSPF TE / opaque LSA documentation",),
    ),
    CapabilitySpec(
        "router.bgp_confederation_rr",
        "ROUTER",
        "BGP confederation and route reflection",
        ("bgp.confederation", "bgp.route_reflector"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("BGP confederation and route reflector documentation",),
    ),
    CapabilitySpec(
        "router.bgp_session_safety",
        "ROUTER",
        "BGP session protection",
        ("bgp.max_prefix", "bgp.gtsm"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("BGP maximum-prefix and TTL security documentation",),
    ),
    CapabilitySpec(
        "router.bgp_graceful_restart",
        "ROUTER",
        "BGP graceful restart",
        ("bgp.graceful_restart",),
        "manual_review",
        ROUTER_PLATFORMS,
        ("BGP graceful restart documentation",),
    ),
    CapabilitySpec(
        "router.pbr_advanced",
        "ROUTER",
        "Advanced policy-based routing",
        ("pbr.track", "pbr.verify"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Policy-based routing tracking and verify-availability documentation",),
    ),
    CapabilitySpec(
        "router.ipv6_tunnel",
        "ROUTER",
        "IPv6 tunnel interfaces",
        ("interface.tunnel6",),
        "manual_review",
        ROUTER_PLATFORMS,
        ("IPv6 tunnel / 6in4 / ISATAP documentation",),
    ),
    CapabilitySpec(
        "router.fhrp_tracking",
        "ROUTER",
        "FHRP tracking",
        ("fhrp.track",),
        "manual_review",
        ROUTER_PLATFORMS,
        ("VRRP/HSRP tracking documentation",),
    ),
    CapabilitySpec(
        "router.acl_advanced_refs",
        "ROUTER",
        "Advanced ACL references",
        ("acl.object_group", "acl.time_range"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("ACL object-group and time-range documentation",),
    ),
    CapabilitySpec(
        "system.ntp_authentication",
        "ROUTER",
        "NTP authentication",
        ("management.ntp_auth",),
        "manual_review",
        SWITCH_PLATFORMS + ROUTER_PLATFORMS,
        ("NTP authentication configuration guides",),
    ),
    CapabilitySpec(
        "system.programmatic_management",
        "ROUTER",
        "Programmatic management APIs",
        ("management.netconf", "management.restconf"),
        "manual_review",
        SWITCH_PLATFORMS + ROUTER_PLATFORMS + FIREWALL_PLATFORMS,
        ("NETCONF/RESTCONF management documentation",),
    ),
    CapabilitySpec(
        "system.streaming_telemetry",
        "ROUTER",
        "Streaming telemetry",
        ("management.telemetry",),
        "manual_review",
        SWITCH_PLATFORMS + ROUTER_PLATFORMS + FIREWALL_PLATFORMS,
        ("Telemetry/gNMI/gRPC configuration guides",),
    ),
    CapabilitySpec(
        "system.flow_export",
        "ROUTER",
        "Flow export / traffic statistics",
        ("telemetry.flow",),
        "manual_review",
        SWITCH_PLATFORMS + ROUTER_PLATFORMS + FIREWALL_PLATFORMS,
        ("NetFlow/NetStream/sFlow documentation",),
    ),
    CapabilitySpec(
        "router.urpf",
        "ROUTER",
        "uRPF source validation",
        ("security.urpf",),
        "manual_review",
        ROUTER_PLATFORMS,
        ("uRPF / reverse path forwarding check documentation",),
    ),
    CapabilitySpec(
        "firewall.proxy_policy",
        "FIREWALL",
        "Proxy policy",
        ("firewall.proxy",),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Firewall proxy policy documentation",),
    ),
    CapabilitySpec(
        "firewall.dns_security",
        "FIREWALL",
        "DNS security",
        ("firewall.dns_security",),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("DNS security profile documentation",),
    ),
    CapabilitySpec(
        "firewall.mail_security",
        "FIREWALL",
        "Mail security",
        ("firewall.mail_security",),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Mail security profile documentation",),
    ),
    CapabilitySpec(
        "firewall.file_blocking",
        "FIREWALL",
        "File blocking",
        ("firewall.file_blocking",),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("File blocking profile documentation",),
    ),
    CapabilitySpec(
        "firewall.sandboxing",
        "FIREWALL",
        "Sandbox analysis",
        ("firewall.sandbox",),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Sandbox / malware analysis documentation",),
    ),
    CapabilitySpec(
        "firewall.ssl_decryption",
        "FIREWALL",
        "SSL decryption",
        ("firewall.decryption",),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("SSL decryption policy documentation",),
    ),
    CapabilitySpec(
        "firewall.high_availability",
        "FIREWALL",
        "High availability",
        ("firewall.ha",),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Firewall HA/HRP documentation",),
    ),
    CapabilitySpec(
        "firewall.virtual_systems",
        "FIREWALL",
        "Virtual systems / multi-tenancy",
        ("firewall.vsys",),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Firewall virtual system / VSYS documentation",),
    ),
    CapabilitySpec(
        "firewall.dynamic_routing",
        "FIREWALL",
        "Firewall routing instances",
        ("firewall.routing",),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Firewall routing and virtual router documentation",),
    ),
    CapabilitySpec(
        "acl_qos",
        "SWITCH",
        "ACL and QoS",
        ("acl", "acl_binding", "qos.classifier", "qos.behavior", "qos.policy", "qos.binding"),
        "auto_subset",
        SWITCH_PLATFORMS + ROUTER_PLATFORMS,
        ("H3C ACL and QoS Configuration Guide", "Cisco IOS XE QoS Configuration Guide", "Ruijie ACL and QoS Configuration"),
    ),
)

CAPABILITY_PROBE_CONFIGS: dict[str, tuple[str, str]] = {
    "system.management": (
        "huawei",
        """sysname EDGE-SW
ntp-service unicast-server 10.0.0.10
info-center loghost 10.0.0.20
snmp-agent community read cipher SECRET
aaa
 local-user admin password cipher SECRET
""",
    ),
    "system.secure_management": (
        "huawei",
        """stelnet server enable
#
ssh user admin authentication-type password
#
pki domain CORP
 certificate request entity ENT
#
crypto pki trustpoint TP
 enrollment terminal
""",
    ),
    "switch.vlan": (
        "huawei",
        """vlan batch 10 20
#
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
""",
    ),
    "switch.trunk_access": (
        "huawei",
        """interface GigabitEthernet0/0/1
 port link-type trunk
 port trunk allow-pass vlan 10 20
#
interface Eth-Trunk1
 mode lacp-static
""",
    ),
    "switch.lacp": (
        "huawei",
        """interface Eth-Trunk1
 mode lacp-static
#
interface GigabitEthernet0/0/1
 eth-trunk 1
""",
    ),
    "switch.stp_mstp": (
        "huawei",
        """stp enable
#
stp region-configuration
 region-name CORE
 instance 1 vlan 10
""",
    ),
    "switch.qinq": (
        "huawei",
        """interface GigabitEthernet0/0/2
 port link-type dot1q-tunnel
 qinq enable
""",
    ),
    "switch.voice_vlan": (
        "huawei",
        "voice-vlan mac-address 0027-0000-0000 mask ffff-0000-0000\n",
    ),
    "switch.lldp": ("huawei", "lldp enable\n"),
    "switch.mac_table": ("huawei", "mac-address static 0011-2233-4455 GigabitEthernet0/0/1 vlan 10\n"),
    "switch.access_security": (
        "huawei",
        """dhcp snooping enable
#
ip source check user-bind enable
#
arp anti-attack check user-bind enable
#
port-security enable
#
storm-control broadcast min-rate 1000 max-rate 2000
""",
    ),
    "switch.access_authentication": (
        "huawei",
        """authentication-profile name dot1x_authen_profile
 dot1x-access-profile dot1x_access
 mac-access-profile mac_access
 access-domain corp force
#
dot1x-access-profile name dot1x_access
#
mac-access-profile name mac_access
#
portal server PORTAL ip 10.10.10.10
#
radius scheme RAD1
 primary authentication 10.10.10.20
 key authentication cipher SECRET
#
domain corp
 authentication lan-access radius-scheme RAD1
#
interface GigabitEthernet0/0/1
 authentication-profile dot1x_authen_profile
 dot1x enable
 mac-authentication enable
""",
    ),
    "switch.stack_virtualization": (
        "h3c",
        """irf member 1 priority 32
#
stack enable
""",
    ),
    "switch.vxlan_evpn": (
        "h3c",
        """vxlan 10010
#
evpn-overlay enable
""",
    ),
    "switch.edge_services": (
        "huawei",
        """poe enable
#
loopback-detection enable
""",
    ),
    "switch.resilience_advanced": (
        "huawei",
        """erps ring 1
 control-vlan 4094
#
smart-link group 1
 protected-vlan reference-instance 1
#
m-lag 1
 peer-link Eth-Trunk10
#
interface Eth-Trunk10
 lacp timeout fast
 lacp preempt enable
""",
    ),
    "switch.vlan_translation": (
        "huawei",
        "vlan mapping 100 map-vlan 200\n",
    ),
    "router.static_route": (
        "huawei",
        """ip route-static 10.0.20.0 255.255.255.0 10.0.10.254
ip route-static 0.0.0.0 0.0.0.0 10.0.10.1 preference 10
""",
    ),
    "router.ospf": (
        "huawei",
        """ospf 1
 router-id 1.1.1.1
 area 0
 network 10.0.0.0 0.0.0.255
 area 1 stub
 passive-interface Vlan10
 area 0 authentication message-digest
 cost 10
 redistribute static
""",
    ),
    "router.bgp": (
        "cisco",
        """router bgp 65000
 bgp router-id 1.1.1.1
 neighbor 10.0.0.2 remote-as 65001
 network 10.10.10.0 mask 255.255.255.0
 neighbor 10.0.0.2 password SECRET
 neighbor 10.0.0.2 route-map EXPORT out
 neighbor 10.0.0.2 update-source Loopback0
 redistribute static
""",
    ),
    "router.rip": (
        "cisco",
        """router rip
 version 2
 network 10.0.0.0
 redistribute static
""",
    ),
    "router.isis": (
        "huawei",
        """isis 1
 network-entity 49.0001.0000.0000.0001.00
 cost-style wide
 import-route static
""",
    ),
    "router.vrf": (
        "cisco",
        """vrf definition MGMT
 rd 65000:1
 route-target export 65000:1
""",
    ),
    "router.route_policy": (
        "cisco",
        """ip prefix-list PL permit 10.0.0.0/24
#
route-map EXPORT permit 10
 match ip address prefix-list PL
""",
    ),
    "router.pbr": (
        "huawei",
        """policy-based-route PBR permit node 10
 if-match acl 3000
 apply ip-address next-hop 10.0.0.254
#
interface GigabitEthernet0/0/1
 ip policy-based-route PBR
""",
    ),
    "router.multicast": (
        "cisco",
        """ip multicast-routing
#
interface GigabitEthernet0/0/2
 ip pim sparse-mode
 igmp enable
""",
    ),
    "router.bfd": ("huawei", "bfd SESSION1 bind peer-ip 10.0.0.2 source-ip 10.0.0.1\n"),
    "router.dhcp": (
        "cisco",
        """ip dhcp pool LAN
 network 10.0.10.0 255.255.255.0
 default-router 10.0.10.1
""",
    ),
    "router.mpls": (
        "huawei",
        """mpls lsr-id 1.1.1.1
mpls
""",
    ),
    "router.nqa_ip_sla": (
        "huawei",
        """nqa test-instance admin ping1
 test-type icmp
 destination-address ipv4 10.0.0.1
#
ip sla 10
 icmp-echo 10.0.0.1
""",
    ),
    "router.fhrp": (
        "mixed",
        """interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
 vrrp vrid 1 virtual-ip 10.0.10.254
#
interface Vlan20
 ip address 10.0.20.1 255.255.255.0
 standby 1 ip 10.0.20.254
""",
    ),
    "router.tunnel": (
        "huawei",
        """interface Tunnel0/0/0
 ip address 10.255.1.1 255.255.255.252
 tunnel-protocol gre
 source 10.0.0.1
 destination 10.0.0.2
""",
    ),
    "router.ipv6_routing": (
        "huawei",
        """ipv6 route-static 2001:db8:10:: 64 2001:db8::1
#
ospfv3 1
 router-id 1.1.1.1
 area 0
#
ipv6 access-list V6-FILTER
 permit tcp any any eq 443
""",
    ),
    "router.dhcp_relay": (
        "huawei",
        """dhcp relay server-address 10.0.0.10
#
interface GigabitEthernet0/0/1
 ip helper-address 10.0.0.10
""",
    ),
    "router.dhcpv6": (
        "huawei",
        """ipv6 dhcp pool V6POOL
 address prefix 2001:db8:10::/64
#
dhcpv6 relay destination 2001:db8::10
#
interface GigabitEthernet0/0/1
 ipv6 dhcp relay destination 2001:db8::10
""",
    ),
    "router.ipv6_first_hop_security": (
        "huawei",
        """ipv6 nd snooping enable
#
ipv6 source guard
#
ipv6 ra guard policy RAGUARD
""",
    ),
    "router.ipv6_interface_services": (
        "huawei",
        """interface GigabitEthernet0/0/1
 ipv6 enable
 ipv6 address 2001:db8:10::1/64
 ipv6 nd ra halt
""",
    ),
    "router.eigrp": (
        "cisco",
        """router eigrp 100
 network 10.0.0.0
 passive-interface default
""",
    ),
    "router.mpls_vpn_advanced": (
        "huawei",
        """mpls ldp
#
mpls te
#
ip vpn-instance CUST-A
 ipv4-family
  route-distinguisher 65000:1
  vpn-target 65000:1 export-extcommunity
""",
    ),
    "router.bgp_advanced_families": (
        "cisco",
        """router bgp 65000
 address-family vpnv4
 address-family l2vpn evpn
 address-family ipv4 flowspec
""",
    ),
    "router.multicast_advanced": (
        "huawei",
        """pim
 static-rp 10.0.0.1
#
msdp
 peer 10.0.0.2 connect-interface LoopBack0
#
interface Vlanif10
 igmp version 3
 igmp static-group 239.1.1.1
""",
    ),
    "router.segment_routing": (
        "cisco",
        """segment-routing
 mpls
#
isis 1
 segment-routing mpls
""",
    ),
    "firewall.objects": (
        "huawei_usg",
        """security-zone name trust
#
ip address-set SRC type object
 address 0 10.0.0.10 mask 255.255.255.255
#
ip service-set HTTP type object
 service 0 protocol tcp destination-port 80
#
object-group ip address WEB-GRP
 network-object host 10.0.0.10
""",
    ),
    "firewall.policy": (
        "huawei_usg",
        """security-policy
 rule name allow-web
  source-zone trust
  destination-zone untrust
  source-address SRC
  destination-address DST
  service HTTP
  action permit
""",
    ),
    "firewall.nat": (
        "huawei_usg",
        """nat-policy
 rule name srcnat
  source-zone trust
  destination-zone untrust
  action source-nat easy-ip
""",
    ),
    "firewall.ipsec": (
        "huawei_usg",
        """interface Tunnel1
 ip address 10.255.1.1 255.255.255.252
 tunnel-protocol ipsec
 source 10.0.0.1
 destination 10.0.0.2
#
ike peer VPN-PEER
 pre-shared-key cipher SECRET
 remote-address 10.0.0.2
#
ipsec policy VPN 1 isakmp
 security acl 3000
 ike-peer VPN-PEER
""",
    ),
    "firewall.utm_profile": (
        "topsec",
        """time-range WORK
 period-range 08:00 to 18:00 working-day
#
url-filter profile WEB-FILTER
 category block gambling
""",
    ),
    "firewall.threat_profiles": (
        "huawei_usg",
        """ips profile IPS-PROFILE
 signature-set critical
#
url-filter profile WEB-FILTER
 category block gambling
#
antivirus profile AV-PROFILE
 scan-mode proxy
#
application-group APP-GRP
 application HTTP
#
user-profile EMPLOYEE
 user-group staff
""",
    ),
    "firewall.remote_access_vpn": (
        "huawei_usg",
        """ssl vpn gateway SSLVPN
 ip address 10.0.0.1 port 443
""",
    ),
    "firewall.threat_advanced": (
        "huawei_usg",
        """dos-policy
 rule name anti-flood
#
dlp profile DLP-PROFILE
 file-type block exe
#
waf profile WAF-PROFILE
 signature enable
""",
    ),
    "firewall.application_delivery": (
        "huawei_usg",
        """load-balance virtual-server VS-WEB
 real-server RS1 10.0.0.10
""",
    ),
    "firewall.session_logging": (
        "hillstone",
        """session timeout tcp 3600
#
traffic log enable
#
log setting security-policy enable
""",
    ),
    "switch.private_vlan": ("cisco", "private-vlan primary 100\n"),
    "switch.registration_protocols": (
        "huawei",
        """gvrp
#
mvrp enable
""",
    ),
    "switch.ethernet_oam": (
        "huawei",
        """ethernet oam enable
#
cfm md MD1 level 3
""",
    ),
    "switch.traffic_mirroring": (
        "cisco",
        """monitor session 1 source interface GigabitEthernet0/1
#
remote-probe vlan 999
""",
    ),
    "switch.device_tracking": ("cisco", "ip device tracking\n"),
    "switch.errdisable": ("cisco", "errdisable recovery cause bpduguard\n"),
    "router.ripng": ("huawei", "ripng 1\n"),
    "router.ospf_traffic_engineering": (
        "huawei",
        """ospf 1
 mpls traffic-eng area 0
""",
    ),
    "router.bgp_confederation_rr": (
        "cisco",
        """router bgp 65000
 bgp confederation identifier 65000
 neighbor 10.0.0.2 route-reflector-client
""",
    ),
    "router.bgp_session_safety": (
        "cisco",
        """router bgp 65000
 neighbor 10.0.0.2 maximum-prefix 1000
 neighbor 10.0.0.2 ttl-security hops 1
""",
    ),
    "router.bgp_graceful_restart": (
        "cisco",
        """router bgp 65000
 bgp graceful-restart
""",
    ),
    "router.pbr_advanced": (
        "huawei",
        """pbr track TRACK1
#
pbr verify-availability enable
""",
    ),
    "router.ipv6_tunnel": (
        "cisco",
        """interface Tunnel10
 ipv6 address 2001:db8:1::1/64
 tunnel mode ipv6ip
""",
    ),
    "router.fhrp_tracking": (
        "huawei",
        """interface Vlanif10
 vrrp vrid 1 track interface GigabitEthernet0/0/1 reduced 30
""",
    ),
    "router.acl_advanced_refs": (
        "huawei",
        """acl number 3000
 rule 5 permit ip source object-group SRC destination any time-range WORK
""",
    ),
    "system.ntp_authentication": ("cisco", "ntp authentication-key 1 md5 SECRET\n"),
    "system.programmatic_management": (
        "huawei",
        """netconf ssh server enable
#
restconf
""",
    ),
    "system.streaming_telemetry": ("huawei", "telemetry\n"),
    "system.flow_export": ("cisco", "ip flow-export destination 10.0.0.10 2055\n"),
    "router.urpf": (
        "cisco",
        """interface GigabitEthernet0/0/1
 ip verify unicast reverse-path
""",
    ),
    "firewall.proxy_policy": (
        "huawei_usg",
        """proxy-policy
 rule name web-proxy
""",
    ),
    "firewall.dns_security": ("huawei_usg", "dns-filter profile DNS-PROTECT\n"),
    "firewall.mail_security": ("huawei_usg", "mail-filter profile MAIL-PROTECT\n"),
    "firewall.file_blocking": ("huawei_usg", "file-blocking profile FILE-BLOCK\n"),
    "firewall.sandboxing": ("huawei_usg", "sandbox profile CLOUD-SANDBOX\n"),
    "firewall.ssl_decryption": (
        "huawei_usg",
        """decryption-policy
 rule name ssl-decrypt
""",
    ),
    "firewall.high_availability": ("huawei_usg", "hrp enable\n"),
    "firewall.virtual_systems": ("huawei_usg", "virtual-system vsys1\n"),
    "firewall.dynamic_routing": ("huawei_usg", "firewall routing-instance VRF1\n"),
    "acl_qos": (
        "huawei",
        """acl number 3000
 rule 5 permit ip source any destination any
#
traffic classifier WEB
 if-match acl 3000
#
traffic behavior LIMIT
 car cir 10240
#
traffic policy EDGE-QOS
 classifier WEB behavior LIMIT
#
interface GigabitEthernet0/0/1
 traffic-filter inbound acl 3000
 traffic-policy EDGE-QOS inbound
""",
    ),
}


def baseline_by_domain() -> dict[str, list[CapabilitySpec]]:
    grouped: dict[str, list[CapabilitySpec]] = {}
    for spec in PRODUCT_CAPABILITY_BASELINE:
        grouped.setdefault(spec.domain, []).append(spec)
    return grouped


def known_module_features() -> set[str]:
    return {feature for spec in PRODUCT_CAPABILITY_BASELINE for feature in spec.module_features}


def capability_coverage_report() -> dict:
    probed_specs = [_spec_with_probe_result(spec) for spec in PRODUCT_CAPABILITY_BASELINE]
    missing_capabilities = [spec["capability_id"] for spec in probed_specs if spec["coverage_status"] == "missing"]
    full_count = sum(1 for spec in probed_specs if spec["coverage_status"] == "covered")
    partial_count = sum(1 for spec in probed_specs if spec["coverage_status"] == "partial")
    by_action: dict[str, int] = {}
    for spec in PRODUCT_CAPABILITY_BASELINE:
        by_action[spec.default_action] = by_action.get(spec.default_action, 0) + 1
    grouped: dict[str, list[dict]] = {}
    for spec in probed_specs:
        grouped.setdefault(spec["domain"], []).append(spec)
    return {
        "summary": {
            "total": len(PRODUCT_CAPABILITY_BASELINE),
            "covered": len(PRODUCT_CAPABILITY_BASELINE) - len(missing_capabilities),
            "full": full_count,
            "partial": partial_count,
            "missing": len(missing_capabilities),
            "by_action": by_action,
        },
        "missing_capabilities": missing_capabilities,
        "domains": grouped,
    }


def _spec_with_probe_result(spec: CapabilitySpec) -> dict:
    data = spec.to_dict()
    vendor, config = CAPABILITY_PROBE_CONFIGS.get(spec.capability_id, ("", ""))
    observed = _probe_module_features(vendor, config) if config else set()
    expected = set(spec.module_features)
    matched = expected & observed
    missing = expected - observed
    if matched and missing:
        coverage_status = "partial"
    elif matched:
        coverage_status = "covered"
    else:
        coverage_status = "missing"
    data.update(
        {
            "probe_vendor": vendor,
            "observed_features": sorted(observed),
            "matched_features": sorted(matched),
            "missing_module_features": sorted(missing),
            "coverage_status": coverage_status,
        }
    )
    return data


def _probe_module_features(vendor: str, config: str) -> set[str]:
    from core.module_graph.builder import build_module_graph

    graph = build_module_graph(config, vendor=vendor)
    return {module.feature for module in graph.modules}
