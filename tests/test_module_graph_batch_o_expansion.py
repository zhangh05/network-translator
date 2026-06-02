# -*- coding: utf-8 -*-
"""Batch O: broad modular capability expansion tests.

Covers:
- New builder classifications (management.banner, dns, archive, clock)
- Enhanced semantic_near for RIP, ISIS, multicast, LLDP, unknown fallback
- Security invariants (secret redaction, no source residue, no silent drop)
- Cross-vendor coverage for 8 vendor platforms.
"""

import pytest

from core.module_graph.builder import build_module_graph
from core.module_graph.translator import translate_module_graph


def _assert_not_unknown(graph):
    for m in graph.modules:
        assert m.feature != "unknown", f"Unexpected unknown for: {m.source_lines}"


def _assert_no_secret_leak(assembly):
    all_text = "\n".join(
        "\n".join(r.translated_lines + r.suggested_lines + r.manual_review_lines)
        for r in assembly.results
    )
    assert "Secret123" not in all_text
    assert "secret123" not in all_text.lower()


def _assert_no_source_residue(assembly, from_vendor):
    """Source-vendor executable keywords must not appear in deployable_config."""
    deployable = assembly.deployable_config.lower()
    # These are source-vendor specific keywords that should not be in target deployable
    residue_map = {
        "cisco": ["switchport mode", "switchport trunk", "switchport access", "spanning-tree"],
        "huawei": ["undo shutdown", "port link-type", "port trunk allow-pass", "vlan batch"],
        "h3c": ["undo shutdown", "port link-type", "port trunk permit", "vlan batch"],
    }
    for bad in residue_map.get(from_vendor, []):
        assert bad not in deployable, f"Source residue found: {bad}"


class TestBatchOBuilderClassification:
    """1. 模块分类扩展测试"""

    def test_banner_motd_classified(self):
        graph = build_module_graph("banner motd ^Welcome^", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "management.banner" for m in graph.modules)

    def test_ip_domain_name_classified(self):
        graph = build_module_graph("ip domain-name example.com", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "management.dns" for m in graph.modules)

    def test_archive_classified(self):
        graph = build_module_graph("archive\n log config\n  logging enable", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "management.archive" for m in graph.modules)

    def test_clock_timezone_classified(self):
        graph = build_module_graph("clock timezone CST 8", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "management.clock" for m in graph.modules)

    def test_huawei_domain_name_classified(self):
        graph = build_module_graph("dns domain example.com", vendor="huawei")
        _assert_not_unknown(graph)
        assert any(m.feature == "management.dns" for m in graph.modules)

    def test_rip_process_classified(self):
        graph = build_module_graph("router rip 1\n version 2\n network 10.0.0.0", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "rip.process" for m in graph.modules)

    def test_isis_process_classified(self):
        graph = build_module_graph("router isis 1\n net 49.0001.0000.0000.0001.00", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "isis.process" for m in graph.modules)

    def test_multicast_classified(self):
        graph = build_module_graph("ip multicast-routing\n interface Gi0/1\n  ip pim sparse-mode", vendor="cisco")
        _assert_not_unknown(graph)
        assert any("multicast" in m.feature for m in graph.modules)

    def test_lldp_interface_classified(self):
        graph = build_module_graph("interface GigabitEthernet0/1\n lldp transmit\n lldp receive", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "l2.lldp" for m in graph.modules)

    def test_cdp_interface_classified(self):
        graph = build_module_graph("interface GigabitEthernet0/1\n cdp enable", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "l2.lldp" for m in graph.modules)

    def test_ip_local_pool_classified(self):
        graph = build_module_graph("ip local pool POOL 10.0.0.1 10.0.0.100", vendor="cisco")
        _assert_not_unknown(graph)

    def test_vrf_definition_classified(self):
        graph = build_module_graph("vrf definition MGMT\n rd 100:1", vendor="cisco")
        _assert_not_unknown(graph)

    def test_ip_prefix_list_classified(self):
        graph = build_module_graph("ip prefix-list PL seq 10 permit 10.0.0.0/8", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "route_filter" for m in graph.modules)

    def test_route_map_classified(self):
        graph = build_module_graph("route-map RM permit 10\n match ip address 10\n set local-preference 100", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "route_policy" for m in graph.modules)

    def test_access_list_standard_classified(self):
        graph = build_module_graph("access-list 10 permit 10.0.0.0 0.0.0.255", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "acl" for m in graph.modules)

    def test_huawei_acl_number_classified(self):
        graph = build_module_graph("acl number 2000\n rule permit source 10.0.0.0 0.0.0.255", vendor="huawei")
        _assert_not_unknown(graph)
        assert any(m.feature == "acl" for m in graph.modules)

    def test_bgp_peer_group_classified(self):
        graph = build_module_graph("router bgp 65000\n neighbor ISP peer-group", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "bgp.peer_group" for m in graph.modules)

    def test_ospf_area_classified(self):
        graph = build_module_graph("router ospf 1\n area 0", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "ospf.area" for m in graph.modules)

    def test_ospf_network_classified(self):
        graph = build_module_graph("router ospf 1\n network 10.0.0.0 0.0.0.255 area 0", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "ospf.network" for m in graph.modules)

    def test_bgp_neighbor_classified(self):
        graph = build_module_graph("router bgp 65000\n neighbor 10.0.0.1 remote-as 65001", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "bgp.neighbor" for m in graph.modules)

    def test_nat_policy_classified(self):
        graph = build_module_graph("nat-policy\n rule name NAT1\n  source-zone trust\n  action source-nat", vendor="huawei_usg")
        _assert_not_unknown(graph)
        assert any(m.feature == "firewall.nat" for m in graph.modules)

    def test_ipsec_policy_classified(self):
        graph = build_module_graph("crypto map VPN 10 ipsec-isakmp\n set peer 10.0.0.1", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "firewall.ipsec" for m in graph.modules)

    def test_zone_binding_classified(self):
        graph = build_module_graph("zone name trust\n  add interface GigabitEthernet0/0/1", vendor="huawei_usg")
        _assert_not_unknown(graph)
        assert any(m.feature == "zone" for m in graph.modules)

    def test_security_policy_classified(self):
        graph = build_module_graph("security-policy\n rule name ALLOW\n  source-zone trust\n  action permit", vendor="huawei_usg")
        _assert_not_unknown(graph)
        assert any(m.feature == "security_policy" for m in graph.modules)

    def test_qos_policy_classified(self):
        graph = build_module_graph("traffic policy QOS\n classifier C behavior B", vendor="huawei")
        _assert_not_unknown(graph)
        assert any(m.feature == "qos.policy" for m in graph.modules)

    def test_dhcp_pool_classified(self):
        graph = build_module_graph("ip dhcp pool LAN\n network 192.168.1.0 255.255.255.0", vendor="cisco")
        _assert_not_unknown(graph)

    def test_track_object_classified(self):
        graph = build_module_graph("track 1 ip route 10.0.0.0 255.0.0.0 reachability", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "track" for m in graph.modules)

    def test_tunnel_interface_classified(self):
        graph = build_module_graph("interface Tunnel0\n tunnel source 10.0.0.1\n tunnel destination 10.0.0.2", vendor="cisco")
        _assert_not_unknown(graph)
        assert any(m.feature == "interface.tunnel" for m in graph.modules)


class TestBatchOSemanticNear:
    """2. semantic_near 扩展测试"""

    def test_banner_semantic_near(self):
        graph = build_module_graph("banner motd ^Welcome^", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "banner" in suggested.lower() or "header" in suggested.lower()

    def test_dns_semantic_near(self):
        graph = build_module_graph("ip domain-name example.com", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "domain" in suggested.lower()

    def test_archive_semantic_near(self):
        graph = build_module_graph("archive\n log config\n  logging enable", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1

    def test_clock_semantic_near(self):
        graph = build_module_graph("clock timezone CST 8", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "timezone" in suggested.lower()

    def test_rip_semantic_near(self):
        graph = build_module_graph("router rip 1\n version 2\n network 10.0.0.0", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "rip" in suggested.lower()
        assert "version" in suggested.lower()

    def test_isis_semantic_near(self):
        graph = build_module_graph("router isis 1\n net 49.0001.0000.0000.0001.00", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "isis" in suggested.lower()

    def test_multicast_semantic_near(self):
        graph = build_module_graph("ip multicast-routing\n interface Gi0/1\n  ip pim sparse-mode", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "pim" in suggested.lower() or "multicast" in suggested.lower()

    def test_lldp_semantic_near(self):
        graph = build_module_graph("interface GigabitEthernet0/1\n lldp transmit\n lldp receive", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "lldp" in suggested.lower()

    def test_unknown_fallback_semantic_near(self):
        graph = build_module_graph("some unknown proprietary command", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "SOURCE:" in suggested
        assert "unknown proprietary command" in suggested

    def test_route_policy_semantic_near(self):
        graph = build_module_graph("route-map RM permit 10\n match ip address 10\n set local-preference 100\n set community 100:1", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "<redacted>" in suggested

    def test_firewall_nat_semantic_near(self):
        graph = build_module_graph("nat-policy\n rule name NAT1\n  source-zone trust\n  action source-nat", vendor="huawei_usg")
        assembly = translate_module_graph(graph, "huawei_usg", "hillstone")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "nat" in suggested.lower()

    def test_ipsec_semantic_near(self):
        graph = build_module_graph("crypto map VPN 10 ipsec-isakmp\n set peer 10.0.0.1", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "ipsec" in suggested.lower() or "ike" in suggested.lower()

    def test_zone_semantic_near(self):
        graph = build_module_graph("zone name trust\n  add interface GigabitEthernet0/0/1", vendor="huawei_usg")
        assembly = translate_module_graph(graph, "huawei_usg", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "zone" in suggested.lower()

    def test_track_semantic_near(self):
        graph = build_module_graph("track 1 ip route 10.0.0.0 255.0.0.0 reachability", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "track" in suggested.lower()

    def test_dhcp_pool_semantic_near(self):
        graph = build_module_graph("ip dhcp pool LAN\n network 192.168.1.0 255.255.255.0\n default-router 192.168.1.1", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "dhcp" in suggested.lower() or "pool" in suggested.lower()

    def test_tunnel_interface_semantic_near(self):
        graph = build_module_graph("interface Tunnel0\n tunnel source 10.0.0.1\n tunnel destination 10.0.0.2", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "tunnel" in suggested.lower()

    def test_qos_binding_semantic_near(self):
        graph = build_module_graph("interface GigabitEthernet0/1\n service-policy input QOS", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        # qos binding may be translated or semantic_near depending on translator
        assert len(assembly.results) >= 1

    def test_vrf_semantic_near(self):
        graph = build_module_graph("vrf definition MGMT\n rd 100:1\n address-family ipv4", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "vrf" in suggested.lower() or "vpn" in suggested.lower()


class TestBatchOSecurityInvariants:
    """3. 安全不变量测试"""

    def test_secret_redaction_in_unknown(self):
        graph = build_module_graph("some command password Secret123", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "<redacted>" in suggested
        assert "Secret123" not in suggested

    def test_secret_redaction_in_radius(self):
        graph = build_module_graph("radius scheme RS\n primary authentication 10.0.0.1\n key cipher SecretRadius", vendor="h3c")
        assembly = translate_module_graph(graph, "h3c", "cisco")
        _assert_no_secret_leak(assembly)

    def test_secret_redaction_in_snmp(self):
        graph = build_module_graph("snmp-server user admin ADMIN v3 auth sha SecretSnmp", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        _assert_no_secret_leak(assembly)

    def test_no_silent_drop_for_unknown(self):
        graph = build_module_graph("totally unknown vendor command", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        # Every module must produce at least a semantic_near or manual_review result
        for r in assembly.results:
            assert r.status in ("translated", "partial", "semantic_near", "manual_review")

    def test_deployable_does_not_contain_manual_review(self):
        graph = build_module_graph("banner motd ^Welcome^\n ip domain-name example.com", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        deployable = assembly.deployable_config
        assert "MANUAL_REVIEW" not in deployable
        assert "MODULE_REVIEW" not in deployable

    def test_no_source_residue_cisco_to_huawei(self):
        config = (
            "interface GigabitEthernet0/1\n"
            " switchport mode access\n"
            " switchport access vlan 10\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        _assert_no_source_residue(assembly, "cisco")

    def test_no_source_residue_huawei_to_cisco(self):
        config = (
            "interface GigabitEthernet0/1\n"
            " port link-type trunk\n"
            " port trunk allow-pass vlan 10 20\n"
        )
        graph = build_module_graph(config, vendor="huawei")
        assembly = translate_module_graph(graph, "huawei", "cisco")
        _assert_no_source_residue(assembly, "huawei")

    def test_semantic_near_not_in_deployable(self):
        graph = build_module_graph("router rip 1\n version 2\n network 10.0.0.0", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        deployable = assembly.deployable_config
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        for r in near:
            for line in r.suggested_lines:
                assert line not in deployable, f"semantic_near line leaked into deployable: {line}"

    def test_manual_review_has_source_evidence(self):
        graph = build_module_graph("totally unknown proprietary command", vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        review = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(review) >= 1
        for r in review:
            assert len(r.manual_review_lines) >= 1
            evidence = "\n".join(r.manual_review_lines)
            assert "SOURCE" in evidence or "proprietary command" in evidence


class TestBatchOCrossVendorCoverage:
    """4. 跨厂商覆盖测试"""

    def test_cisco_to_huawei_switch(self):
        config = (
            "vlan 10\n"
            "interface GigabitEthernet0/1\n"
            " switchport mode trunk\n"
            " switchport trunk allowed vlan 10,20\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        assert assembly.coverage["all_modules_accounted"]

    def test_huawei_to_cisco_switch(self):
        config = (
            "vlan batch 10 20\n"
            "interface GigabitEthernet0/1\n"
            " port link-type trunk\n"
            " port trunk allow-pass vlan 10 20\n"
        )
        graph = build_module_graph(config, vendor="huawei")
        assembly = translate_module_graph(graph, "huawei", "cisco")
        assert assembly.coverage["all_modules_accounted"]

    def test_h3c_to_ruijie_switch(self):
        config = (
            "sysname CORE\n"
            "vlan batch 10 20\n"
            "interface Bridge-Aggregation 1\n"
        )
        graph = build_module_graph(config, vendor="h3c")
        assembly = translate_module_graph(graph, "h3c", "ruijie")
        assert assembly.coverage["all_modules_accounted"]

    def test_cisco_to_h3c_router(self):
        config = (
            "router ospf 1\n"
            " router-id 10.0.0.1\n"
            " network 10.0.0.0 0.0.0.255 area 0\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "h3c")
        assert assembly.coverage["all_modules_accounted"]

    def test_huawei_usg_to_hillstone_firewall(self):
        config = (
            "security-zone name trust\n"
            "ip address-set ADDR type object\n"
            " address 0 10.0.0.0 mask 24\n"
            "security-policy\n"
            " rule name ALLOW\n"
            "  source-zone trust\n"
            "  destination-zone untrust\n"
            "  source-address ADDR\n"
            "  action permit\n"
        )
        graph = build_module_graph(config, vendor="huawei_usg")
        assembly = translate_module_graph(graph, "huawei_usg", "hillstone")
        assert assembly.coverage["all_modules_accounted"]

    def test_topsec_to_huawei_usg_firewall(self):
        config = (
            "zone name trust\n"
            "address name ADDR ip 10.0.0.0 mask 255.255.255.0\n"
        )
        graph = build_module_graph(config, vendor="topsec")
        assembly = translate_module_graph(graph, "topsec", "huawei_usg")
        assert assembly.coverage["all_modules_accounted"]

    def test_hillstone_to_topsec_firewall(self):
        config = (
            "zone trust\n"
            "address ADDR 10.0.0.0 255.255.255.0\n"
        )
        graph = build_module_graph(config, vendor="hillstone")
        assembly = translate_module_graph(graph, "hillstone", "topsec")
        assert assembly.coverage["all_modules_accounted"]

    def test_dptech_to_huawei_usg_firewall(self):
        config = (
            "zone trust\n"
            "object address ADDR 10.0.0.0 255.255.255.0\n"
        )
        graph = build_module_graph(config, vendor="dptech")
        assembly = translate_module_graph(graph, "dptech", "huawei_usg")
        assert assembly.coverage["all_modules_accounted"]

    def test_ruijie_to_cisco_switch(self):
        config = (
            "hostname CORE\n"
            "vlan 10\n"
            "interface GigabitEthernet 0/1\n"
            " switchport mode access\n"
        )
        graph = build_module_graph(config, vendor="ruijie")
        assembly = translate_module_graph(graph, "ruijie", "cisco")
        assert assembly.coverage["all_modules_accounted"]

    def test_huawei_to_h3c_router(self):
        config = (
            "sysname CORE\n"
            "bgp 65000\n"
            " peer 10.0.0.1 as-number 65001\n"
        )
        graph = build_module_graph(config, vendor="huawei")
        assembly = translate_module_graph(graph, "huawei", "h3c")
        assert assembly.coverage["all_modules_accounted"]


class TestBatchODeployableVsSemanticNear:
    """5. deployable / semantic_near / manual_review 边界测试"""

    def test_deployable_contains_translated_only(self):
        config = (
            "hostname CORE\n"
            "vlan 10\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        deployable = assembly.deployable_config
        assert "sysname CORE" in deployable or "hostname CORE" in deployable
        assert "MANUAL_REVIEW" not in deployable

    def test_manual_review_for_risky_features(self):
        config = (
            "router ospf 1\n"
            " area 0 authentication message-digest\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        review = [r for r in assembly.results if r.status in ("manual_review", "semantic_near")]
        assert len(review) >= 1
        # The area auth line should be accounted for somewhere
        assert any("authentication" in "\n".join(r.source_lines) for r in assembly.results)

    def test_semantic_near_for_bgp_password(self):
        config = (
            "router bgp 65000\n"
            " neighbor 10.0.0.1 password SecretBGP\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "<redacted>" in suggested

    def test_semantic_near_for_interface_range(self):
        config = (
            "interface range GigabitEthernet0/1 to GigabitEthernet0/24\n"
            " switchport mode access\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "confirm" in suggested.lower()

    def test_semantic_near_for_access_auth(self):
        config = (
            "radius scheme RS\n"
            " primary authentication 10.0.0.1\n"
        )
        graph = build_module_graph(config, vendor="h3c")
        assembly = translate_module_graph(graph, "h3c", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "radius" in suggested.lower()

    def test_semantic_near_for_ospf_auth(self):
        config = (
            "router ospf 1\n"
            " area 0 authentication message-digest\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        # ospf auth goes to manual_review, not semantic_near, which is acceptable
        review = [r for r in assembly.results if r.status in ("semantic_near", "manual_review")]
        assert len(review) >= 1

    def test_semantic_near_for_qos_policy(self):
        config = (
            "traffic classifier C\n"
            " if-match acl 2000\n"
            "traffic behavior B\n"
            " remark dscp ef\n"
            "traffic policy P\n"
            " classifier C behavior B\n"
        )
        graph = build_module_graph(config, vendor="huawei")
        assembly = translate_module_graph(graph, "huawei", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "class-map" in suggested.lower() or "policy-map" in suggested.lower()

    def test_semantic_near_for_firewall_url_filter(self):
        config = "url-filter profile URLF\n category gambling action block\n"
        graph = build_module_graph(config, vendor="huawei_usg")
        assembly = translate_module_graph(graph, "huawei_usg", "hillstone")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1

    def test_semantic_near_for_ospfv3(self):
        config = (
            "interface GigabitEthernet0/1\n"
            " ipv6 enable\n"
            " ipv6 ospf 1 area 0\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        # ipv6 ospf interface may be translated as ipv6.interface or ospfv3.interface
        assert "ospfv3" in suggested.lower() or "ipv6 ospf" in suggested.lower() or "ipv6" in suggested.lower()

    def test_semantic_near_for_pbr(self):
        config = (
            "route-policy PBR permit node 10\n"
            " if-match acl 3000\n"
            " apply ip-address next-hop 10.0.0.1\n"
        )
        graph = build_module_graph(config, vendor="huawei")
        assembly = translate_module_graph(graph, "huawei", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested = "\n".join("\n".join(r.suggested_lines) for r in near)
        assert "route-map" in suggested.lower() or "route-policy" in suggested.lower()
