# -*- coding: utf-8 -*-
"""Additional product breadth coverage for IPv6 and edge services."""

from core.module_graph import build_module_graph
from core.module_graph.capability_taxonomy import PRODUCT_CAPABILITY_BASELINE, capability_coverage_report


def _first(graph, feature):
    modules = graph.by_feature(feature)
    assert modules, f"missing feature {feature}"
    return modules[0]


def test_ipv6_static_route_ospfv3_and_ipv6_acl_are_typed_modules():
    config = """ipv6 route-static 2001:db8:10:: 64 2001:db8::1
#
ospfv3 1
 router-id 1.1.1.1
 area 0
#
ipv6 access-list V6-FILTER
 permit tcp any any eq 443
"""
    graph = build_module_graph(config, vendor="huawei")

    route = _first(graph, "ipv6.static_route")
    ospfv3 = _first(graph, "ospfv3.process")
    acl = _first(graph, "ipv6.acl")

    assert route.status == "manual_review"
    assert ospfv3.status == "manual_review"
    assert acl.status == "manual_review"
    assert route.manual_review_reason
    assert ospfv3.manual_review_reason
    assert acl.manual_review_reason


def test_dhcp_relay_poe_and_loop_detection_are_not_unknown():
    config = """dhcp relay server-address 10.0.0.10
#
poe enable
#
loopback-detection enable
"""
    graph = build_module_graph(config, vendor="huawei")

    for feature in ("dhcp.relay", "l2.poe", "l2.loop_detection"):
        module = _first(graph, feature)
        assert module.status == "manual_review"
        assert module.source_lines


def test_cisco_eigrp_is_cisco_specific_manual_review():
    config = """router eigrp 100
 network 10.0.0.0
 passive-interface default
"""
    graph = build_module_graph(config, vendor="cisco")

    eigrp = _first(graph, "eigrp")
    assert eigrp.status == "manual_review"
    assert "Cisco" in eigrp.manual_review_reason or "EIGRP" in eigrp.manual_review_reason


def test_product_capability_baseline_includes_ipv6_and_edge_services():
    ids = {spec.capability_id for spec in PRODUCT_CAPABILITY_BASELINE}

    for capability in (
        "switch.edge_services",
        "router.ipv6_routing",
        "router.dhcp_relay",
        "router.eigrp",
    ):
        assert capability in ids


def test_ipv6_and_edge_service_capabilities_are_probe_covered():
    report = capability_coverage_report()
    by_id = {spec["capability_id"]: spec for specs in report["domains"].values() for spec in specs}

    for capability in (
        "switch.edge_services",
        "router.ipv6_routing",
        "router.dhcp_relay",
        "router.eigrp",
    ):
        assert by_id[capability]["coverage_status"] == "covered"
        assert by_id[capability]["missing_module_features"] == []
