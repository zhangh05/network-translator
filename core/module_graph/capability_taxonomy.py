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
        "firewall.session_logging",
        "FIREWALL",
        "Session and audit logging",
        ("firewall.session", "firewall.logging"),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Huawei USG logging/session guides", "Hillstone StoneOS logging/session documentation", "Topsec firewall audit documentation", "DPtech firewall logging documentation"),
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
    "firewall.session_logging": (
        "hillstone",
        """session timeout tcp 3600
#
traffic log enable
#
log setting security-policy enable
""",
    ),
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
