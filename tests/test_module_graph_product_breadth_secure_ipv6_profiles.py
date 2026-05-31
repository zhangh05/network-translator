# -*- coding: utf-8 -*-
"""Product breadth coverage for secure management, IPv6 interface, and firewall profiles."""

from core.module_graph import build_module_graph
from core.module_graph.capability_taxonomy import PRODUCT_CAPABILITY_BASELINE, capability_coverage_report


def _first(graph, feature):
    modules = graph.by_feature(feature)
    assert modules, f"missing feature {feature}"
    return modules[0]


def test_interface_ipv6_nd_ra_and_dhcp_relay_binding_are_child_modules():
    config = """interface GigabitEthernet0/0/1
 ipv6 enable
 ipv6 address 2001:db8:10::1/64
 ipv6 nd ra halt
 ipv6 dhcp relay destination 2001:db8::10
 ip helper-address 10.0.0.10
"""
    graph = build_module_graph(config, vendor="huawei")

    for feature in ("ipv6.interface", "ipv6.nd_ra", "dhcp.relay.binding"):
        module = _first(graph, feature)
        assert module.status == "manual_review"
        assert "interface:GigabitEthernet0/0/1" in module.consumes
        assert module.manual_review_reason


def test_secure_management_ssh_and_pki_are_typed_review_modules():
    config = """stelnet server enable
#
ssh user admin authentication-type password
#
pki domain CORP
 certificate request entity ENT
#
crypto pki trustpoint TP
 enrollment terminal
"""
    graph = build_module_graph(config, vendor="huawei")

    ssh = _first(graph, "management.ssh")
    pki = _first(graph, "management.pki")

    assert ssh.status == "manual_review"
    assert pki.status == "manual_review"
    assert "SSH" in ssh.manual_review_reason or "管理面" in ssh.manual_review_reason
    assert "PKI" in pki.manual_review_reason or "证书" in pki.manual_review_reason


def test_firewall_threat_profiles_are_split_by_security_function():
    config = """ips profile IPS-PROFILE
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
"""
    graph = build_module_graph(config, vendor="huawei_usg")

    for feature in (
        "firewall.ips",
        "firewall.url_filter",
        "firewall.av",
        "firewall.application",
        "firewall.user_id",
    ):
        module = _first(graph, feature)
        assert module.status == "manual_review"
        assert module.manual_review_reason


def test_product_capability_baseline_includes_secure_management_ipv6_interface_and_threat_profiles():
    ids = {spec.capability_id for spec in PRODUCT_CAPABILITY_BASELINE}

    for capability in (
        "system.secure_management",
        "router.ipv6_interface_services",
        "firewall.threat_profiles",
    ):
        assert capability in ids


def test_new_secure_ipv6_profile_capabilities_are_probe_covered():
    report = capability_coverage_report()
    by_id = {spec["capability_id"]: spec for specs in report["domains"].values() for spec in specs}

    for capability in (
        "system.secure_management",
        "router.ipv6_interface_services",
        "firewall.threat_profiles",
    ):
        assert by_id[capability]["coverage_status"] == "covered"
        assert by_id[capability]["missing_module_features"] == []
