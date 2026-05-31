# -*- coding: utf-8 -*-
"""Product-document aligned capability breadth tests."""

from core.module_graph import build_module_graph
from core.module_graph.capability_taxonomy import (
    PRODUCT_CAPABILITY_BASELINE,
    baseline_by_domain,
    capability_coverage_report,
)


DOC_PATH = "docs/PRODUCT_CAPABILITY_BASELINE.md"


def test_baseline_covers_three_device_domains_and_eight_platforms():
    domains = {spec.domain for spec in PRODUCT_CAPABILITY_BASELINE}
    vendors = {vendor for spec in PRODUCT_CAPABILITY_BASELINE for vendor in spec.vendor_platforms}

    assert {"SWITCH", "ROUTER", "FIREWALL"}.issubset(domains)
    assert {
        "cisco_ios_xe",
        "h3c_comware",
        "huawei_vrp",
        "huawei_usg",
        "ruijie_rgos",
        "hillstone_stoneos",
        "topsec_tos",
        "dptech_fw",
    }.issubset(vendors)


def test_baseline_contains_product_breadth_beyond_ospf_bgp():
    capability_ids = {spec.capability_id for spec in PRODUCT_CAPABILITY_BASELINE}

    for expected in (
        "switch.qinq",
        "switch.voice_vlan",
        "switch.lldp",
        "router.rip",
        "router.isis",
        "router.pbr",
        "router.multicast",
        "firewall.nat",
        "firewall.ipsec",
        "firewall.utm_profile",
    ):
        assert expected in capability_ids


def test_baseline_entries_have_doc_evidence_and_default_action():
    for spec in PRODUCT_CAPABILITY_BASELINE:
        assert spec.evidence_refs, f"{spec.capability_id} must cite product documentation"
        assert spec.default_action in {"auto_subset", "manual_review", "identify_only"}
        assert spec.module_features, f"{spec.capability_id} must map to module features"


def test_baseline_by_domain_groups_specs():
    grouped = baseline_by_domain()

    assert grouped["SWITCH"]
    assert grouped["ROUTER"]
    assert grouped["FIREWALL"]
    assert any(spec.capability_id == "router.route_policy" for spec in grouped["ROUTER"])


def test_capability_coverage_report_marks_existing_module_features():
    report = capability_coverage_report()

    assert report["summary"]["total"] >= 20
    assert report["summary"]["covered"] >= 15
    assert "switch.qinq" not in report["missing_capabilities"]
    assert "firewall.ipsec" not in report["missing_capabilities"]


def test_l2_advanced_features_are_split_into_manual_review_modules():
    config = """voice-vlan mac-address 0027-0000-0000 mask ffff-0000-0000
#
interface GigabitEthernet0/0/1
 port link-type trunk
 qinq enable
#
lldp enable
#
mac-address static 0011-2233-4455 GigabitEthernet0/0/1 vlan 10
#
stp region-configuration
 instance 1 vlan 10
"""
    graph = build_module_graph(config, vendor="huawei")

    for feature in ("l2.voice_vlan", "l2.qinq", "l2.lldp", "l2.mac_table", "stp.mstp"):
        modules = graph.by_feature(feature)
        assert modules, f"{feature} should be represented as its own module"
        assert modules[0].status == "manual_review"
        assert modules[0].manual_review_reason


def test_product_capability_baseline_doc_lists_sources_and_actions():
    with open(DOC_PATH, encoding="utf-8") as f:
        doc = f.read()

    for text in (
        "Cisco IOS XE",
        "Huawei VRP Ethernet Switching",
        "H3C Comware",
        "Ruijie RGOS",
        "Huawei USG",
        "Hillstone StoneOS",
        "DPtech",
        "auto_subset",
        "manual_review",
        "identify_only",
    ):
        assert text in doc


def test_product_capability_report_script_path_documented():
    with open(DOC_PATH, encoding="utf-8") as f:
        doc = f.read()

    assert "scripts/report_product_capability_baseline.py" in doc
    assert "reports/product_capability_baseline.json" in doc
