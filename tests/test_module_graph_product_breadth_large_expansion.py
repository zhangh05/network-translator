# -*- coding: utf-8 -*-
"""Large product breadth expansion for high-risk network capabilities."""

from core.module_graph import build_module_graph
from core.module_graph.capability_taxonomy import PRODUCT_CAPABILITY_BASELINE, capability_coverage_report


def _first(graph, feature):
    modules = graph.by_feature(feature)
    assert modules, f"missing feature {feature}"
    return modules[0]


def test_l2_ring_mlag_vlan_mapping_and_lacp_tuning_are_review_modules():
    config = """erps ring 1
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
#
vlan mapping 100 map-vlan 200
"""
    graph = build_module_graph(config, vendor="huawei")

    for feature in ("l2.ring_protection", "l2.smart_link", "l2.mlag", "lacp.tuning", "l2.vlan_mapping"):
        module = _first(graph, feature)
        assert module.status == "manual_review"
        assert module.manual_review_reason


def test_ipv6_first_hop_security_and_dhcpv6_are_review_modules():
    config = """ipv6 dhcp pool V6POOL
 address prefix 2001:db8:10::/64
#
dhcpv6 relay destination 2001:db8::10
#
ipv6 nd snooping enable
#
ipv6 source guard
#
ipv6 ra guard policy RAGUARD
#
interface GigabitEthernet0/0/1
 ipv6 nd snooping trust
 ipv6 dhcp relay destination 2001:db8::10
"""
    graph = build_module_graph(config, vendor="huawei")

    for feature in ("dhcpv6.pool", "dhcpv6.relay", "ipv6.nd_snooping", "ipv6.source_guard", "ipv6.ra_guard", "dhcpv6.relay.binding"):
        module = _first(graph, feature)
        assert module.status == "manual_review"


def test_mpls_l3vpn_and_bgp_address_families_are_review_modules():
    config = """mpls ldp
#
mpls te
#
traffic-eng tunnels
#
router bgp 65000
 address-family vpnv4
  neighbor 10.0.0.2 activate
 address-family l2vpn evpn
  neighbor 10.0.0.2 activate
#
ip vpn-instance CUST-A
 ipv4-family
  route-distinguisher 65000:1
  vpn-target 65000:1 export-extcommunity
"""
    graph = build_module_graph(config, vendor="huawei")

    for feature in ("mpls.ldp", "mpls.te", "bgp.vpnv4", "bgp.evpn", "mpls.l3vpn"):
        module = _first(graph, feature)
        assert module.status == "manual_review"
        assert module.manual_review_reason


def test_multicast_rp_msdp_and_advanced_igmp_are_review_modules():
    config = """pim
 static-rp 10.0.0.1
#
msdp
 peer 10.0.0.2 connect-interface LoopBack0
#
interface Vlanif10
 igmp version 3
 igmp static-group 239.1.1.1
 pim sparse-mode
"""
    graph = build_module_graph(config, vendor="huawei")

    for feature in ("multicast.rp", "multicast.msdp", "multicast.igmp_tuning", "multicast.interface"):
        module = _first(graph, feature)
        assert module.status == "manual_review"


def test_firewall_sslvpn_dos_dlp_waf_and_load_balance_are_review_modules():
    config = """ssl vpn gateway SSLVPN
 ip address 10.0.0.1 port 443
#
dos-policy
 rule name anti-flood
#
dlp profile DLP-PROFILE
 file-type block exe
#
waf profile WAF-PROFILE
 signature enable
#
load-balance virtual-server VS-WEB
 real-server RS1 10.0.0.10
"""
    graph = build_module_graph(config, vendor="huawei_usg")

    for feature in ("firewall.ssl_vpn", "firewall.dos", "firewall.dlp", "firewall.waf", "firewall.load_balance"):
        module = _first(graph, feature)
        assert module.status == "manual_review"
        assert module.manual_review_reason


def test_segment_routing_and_bgp_flowspec_are_review_modules():
    config = """segment-routing
 mpls
#
isis 1
 segment-routing mpls
#
router bgp 65000
 address-family ipv4 flowspec
  neighbor 10.0.0.2 activate
"""
    graph = build_module_graph(config, vendor="cisco")

    for feature in ("segment_routing", "segment_routing.binding", "bgp.flowspec"):
        module = _first(graph, feature)
        assert module.status == "manual_review"


def test_product_capability_baseline_includes_large_expansion_ids():
    ids = {spec.capability_id for spec in PRODUCT_CAPABILITY_BASELINE}
    for capability in (
        "switch.resilience_advanced",
        "switch.vlan_translation",
        "router.ipv6_first_hop_security",
        "router.dhcpv6",
        "router.mpls_vpn_advanced",
        "router.bgp_advanced_families",
        "router.multicast_advanced",
        "router.segment_routing",
        "firewall.remote_access_vpn",
        "firewall.threat_advanced",
        "firewall.application_delivery",
    ):
        assert capability in ids


def test_large_expansion_capabilities_are_probe_covered():
    report = capability_coverage_report()
    by_id = {spec["capability_id"]: spec for specs in report["domains"].values() for spec in specs}
    for capability in (
        "switch.resilience_advanced",
        "switch.vlan_translation",
        "router.ipv6_first_hop_security",
        "router.dhcpv6",
        "router.mpls_vpn_advanced",
        "router.bgp_advanced_families",
        "router.multicast_advanced",
        "router.segment_routing",
        "firewall.remote_access_vpn",
        "firewall.threat_advanced",
        "firewall.application_delivery",
    ):
        assert by_id[capability]["coverage_status"] == "covered"
        assert by_id[capability]["missing_module_features"] == []
