# -*- coding: utf-8 -*-
"""Product breadth module-graph regression tests."""

from core.module_graph import build_module_graph
from core.module_graph.capability_taxonomy import PRODUCT_CAPABILITY_BASELINE, capability_coverage_report


def _features(config, vendor="huawei"):
    return {module.feature for module in build_module_graph(config, vendor=vendor).modules}


def _first(graph, feature):
    modules = graph.by_feature(feature)
    assert modules, f"missing feature {feature}"
    return modules[0]


def test_l2_access_security_features_are_not_unknown():
    config = """dhcp snooping enable
#
ip source check user-bind enable
#
arp anti-attack check user-bind enable
#
port-security enable
#
storm-control broadcast min-rate 1000 max-rate 2000
"""
    graph = build_module_graph(config, vendor="huawei")

    for feature in ("l2.dhcp_snooping", "l2.source_guard", "l2.arp_security", "l2.port_security", "l2.storm_control"):
        module = _first(graph, feature)
        assert module.status == "manual_review"
        assert module.manual_review_reason


def test_stack_virtualization_and_overlay_features_are_review_modules():
    config = """irf member 1 priority 32
#
stack enable
#
vxlan 10010
#
evpn-overlay enable
"""
    graph = build_module_graph(config, vendor="h3c")

    for feature in ("platform.stack", "overlay.vxlan", "overlay.evpn"):
        module = _first(graph, feature)
        assert module.status == "manual_review"
        assert module.source_lines


def test_mpls_and_nqa_ip_sla_are_typed_review_modules():
    config = """mpls lsr-id 1.1.1.1
#
nqa test-instance admin ping1
 test-type icmp
 destination-address ipv4 10.0.0.1
#
ip sla 10
 icmp-echo 10.0.0.1
"""
    graph = build_module_graph(config, vendor="huawei")

    for feature in ("mpls", "nqa", "ip_sla"):
        module = _first(graph, feature)
        assert module.status == "manual_review"
        assert module.manual_review_reason


def test_hsrp_is_split_from_interface_like_vrrp():
    config = """interface Vlan10
 ip address 10.0.10.1 255.255.255.0
 standby 1 ip 10.0.10.254
 standby 1 priority 120
"""
    graph = build_module_graph(config, vendor="cisco")

    svi = _first(graph, "interface.svi")
    hsrp = _first(graph, "fhrp.hsrp")

    assert "standby 1 ip" not in "\n".join(svi.source_lines)
    assert hsrp.status == "manual_review"
    assert "interface:Vlan10" in hsrp.consumes
    assert "hsrp:Vlan10:1" in hsrp.provides
    assert svi.module_id in hsrp.depends_on


def test_firewall_session_and_logging_are_review_modules():
    config = """session timeout tcp 3600
#
traffic log enable
#
log setting security-policy enable
"""
    graph = build_module_graph(config, vendor="hillstone")

    for feature in ("firewall.session", "firewall.logging"):
        module = _first(graph, feature)
        assert module.status == "manual_review"
        assert module.manual_review_reason


def test_product_capability_baseline_includes_expanded_breadth():
    ids = {spec.capability_id for spec in PRODUCT_CAPABILITY_BASELINE}

    for capability in (
        "switch.access_security",
        "switch.stack_virtualization",
        "switch.vxlan_evpn",
        "router.mpls",
        "router.nqa_ip_sla",
        "router.fhrp",
        "router.tunnel",
        "firewall.session_logging",
    ):
        assert capability in ids


def test_expanded_breadth_is_probe_covered():
    report = capability_coverage_report()
    by_id = {spec["capability_id"]: spec for specs in report["domains"].values() for spec in specs}

    for capability in (
        "switch.access_security",
        "switch.stack_virtualization",
        "switch.vxlan_evpn",
        "router.mpls",
        "router.nqa_ip_sla",
        "router.fhrp",
        "router.tunnel",
        "firewall.session_logging",
    ):
        assert by_id[capability]["coverage_status"] == "covered"
        assert by_id[capability]["matched_features"]
