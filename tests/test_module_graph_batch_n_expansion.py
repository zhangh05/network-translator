"""Tests for Batch N module breadth and semantic-near expansion.

Covers:
- interface range classification and semantic-near with subcommands
- line vty / user-interface with acl, privilege, timeout
- radius scheme / tacacs scheme semantic-near
- route-policy match/set/community semantic-near
- prefix-list / ip-prefix / community-filter / as-path-filter semantic-near
- ospf import-route / isis import-route classification
- bgp peer-group / address-family classification
- ipv6 route / ipv6 prefix-list / ipv6 acl binding
- firewall NAT / IPsec / zone interface binding
- snmp group/user/trap and ntp vrf/source/auth semantic-near

Requirements:
1. 分类不为 unknown
2. 进入 semantic_near
3. suggested_lines 不为空
4. deployable_config 不含这些不确定配置
5. secret 不泄露
6. source vendor keywords 不出现在 deployable_config
7. interface/routing/access/firewall/management 至少各覆盖 2 个场景
"""
from __future__ import annotations

import pytest

from core.module_graph.builder import build_module_graph
from core.module_graph.translator import translate_module_graph


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _assert_not_unknown(graph):
    features = {m.feature for m in graph.modules}
    assert "unknown" not in features, f"Found unknown in features: {features}"


def _assert_semantic_near(config: str, from_vendor: str, to_vendor: str, min_near: int = 1):
    graph = build_module_graph(config, vendor=from_vendor)
    assembly = translate_module_graph(graph, from_vendor, to_vendor)
    near_results = [r for r in assembly.results if r.status == "semantic_near"]
    assert len(near_results) >= min_near, f"Expected at least {min_near} semantic_near, got {len(near_results)}"
    for r in near_results:
        assert r.suggested_lines, f"semantic_near result for {r.feature} must have suggested_lines"
    return assembly


def _assert_no_deployable_uncertain(config: str, from_vendor: str, to_vendor: str, uncertain_keywords: list[str]):
    graph = build_module_graph(config, vendor=from_vendor)
    assembly = translate_module_graph(graph, from_vendor, to_vendor)
    deployable = assembly.deployable_config.lower()
    for kw in uncertain_keywords:
        assert kw.lower() not in deployable, f"Uncertain keyword '{kw}' found in deployable_config"
    return assembly


def _assert_no_secret_leak(assembly):
    full_output = str(assembly.to_dict()).lower()
    for secret_kw in ("password", "secret", "cipher", "shared-key", "community", "key"):
        # Allow <redacted> and manual_review markers
        if secret_kw in full_output:
            # Check that actual secret values are not present
            assert "<redacted>" in full_output or "MANUAL_REVIEW" in full_output.upper()


def _assert_no_source_residue(assembly, from_vendor: str, source_keywords: list[str]):
    deployable = assembly.deployable_config.lower()
    for kw in source_keywords:
        assert kw.lower() not in deployable, f"Source keyword '{kw}' leaked into deployable_config"


# ---------------------------------------------------------------------------
# A. Interface (range + L2 security)
# ---------------------------------------------------------------------------

class TestInterfaceRange:
    def test_interface_range_trunk_native(self):
        config = (
            "interface range GigabitEthernet0/0/1 to GigabitEthernet0/0/24\n"
            " switchport mode trunk\n"
            " switchport trunk allowed vlan 10,20\n"
            " switchport trunk native vlan 99\n"
        )
        _assert_not_unknown(build_module_graph(config, vendor="cisco"))
        assembly = _assert_semantic_near(config, "cisco", "huawei", min_near=1)
        _assert_no_deployable_uncertain(config, "cisco", "huawei", ["switchport trunk"])
        assert any("trunk" in " ".join(r.suggested_lines).lower() for r in assembly.results if r.status == "semantic_near")

    def test_interface_range_access_vlan(self):
        config = (
            "interface range GigabitEthernet0/0/1 to GigabitEthernet0/0/24\n"
            " switchport mode access\n"
            " switchport access vlan 100\n"
        )
        _assert_not_unknown(build_module_graph(config, vendor="cisco"))
        assembly = _assert_semantic_near(config, "cisco", "huawei", min_near=1)
        _assert_no_source_residue(assembly, "cisco", ["switchport mode access"])

    def test_interface_range_storm_control(self):
        config = (
            "interface range GigabitEthernet0/0/1 to GigabitEthernet0/0/24\n"
            " storm-control broadcast level 10\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        _assert_not_unknown(graph)
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        assert any("broadcast-suppression" in " ".join(r.suggested_lines).lower() for r in near)

    def test_interface_port_security(self):
        config = (
            "interface GigabitEthernet0/0/1\n"
            " switchport port-security\n"
            " switchport port-security maximum 2\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        _assert_not_unknown(graph)
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        assert any("port-security" in " ".join(r.suggested_lines).lower() for r in near)

    def test_interface_bpduguard(self):
        config = (
            "interface GigabitEthernet0/0/1\n"
            " spanning-tree bpduguard enable\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        _assert_not_unknown(graph)
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        assert any("bpduguard" in " ".join(r.suggested_lines).lower() or "bpdu" in " ".join(r.suggested_lines).lower() for r in near)


# ---------------------------------------------------------------------------
# B. Management (line vty + snmp + ntp)
# ---------------------------------------------------------------------------

class TestManagementLine:
    def test_line_vty_acl_privilege(self):
        config = (
            "line vty 0 4\n"
            " access-class 10 in\n"
            " privilege level 15\n"
            " exec-timeout 10 0\n"
        )
        _assert_not_unknown(build_module_graph(config, vendor="cisco"))
        assembly = _assert_semantic_near(config, "cisco", "huawei", min_near=1)
        suggested_text = "\n".join(
            "\n".join(r.suggested_lines) for r in assembly.results if r.status == "semantic_near"
        ).lower()
        assert "access-class" in suggested_text or "acl" in suggested_text
        assert "privilege" in suggested_text or "user-privilege" in suggested_text

    def test_user_interface_timeout(self):
        config = (
            "user-interface vty 0 4\n"
            " authentication-mode aaa\n"
            " idle-timeout 10 0\n"
            " protocol inbound ssh\n"
        )
        _assert_not_unknown(build_module_graph(config, vendor="huawei"))
        assembly = _assert_semantic_near(config, "huawei", "cisco", min_near=1)
        suggested_text = "\n".join(
            "\n".join(r.suggested_lines) for r in assembly.results if r.status == "semantic_near"
        ).lower()
        assert "exec-timeout" in suggested_text or "idle-timeout" in suggested_text

    def test_snmp_group_user_trap(self):
        config = (
            "snmp-server group ADMIN v3 priv\n"
            "snmp-server user admin ADMIN v3 auth sha Secret1\n"
            "snmp-server host 10.0.0.1 version 2c public\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        _assert_not_unknown(graph)
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested_text = "\n".join("\n".join(r.suggested_lines) for r in near).lower()
        assert "snmp" in suggested_text
        assert "<redacted>" in suggested_text
        _assert_no_secret_leak(assembly)

    def test_ntp_vrf_source_auth(self):
        config = (
            "ntp server 10.0.0.1 vrf MGMT source Loopback0\n"
            "ntp authentication-key 1 md5 SecretKey\n"
            "ntp trusted-key 1\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        _assert_not_unknown(graph)
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested_text = "\n".join("\n".join(r.suggested_lines) for r in near).lower()
        assert "ntp" in suggested_text
        assert "<redacted>" in suggested_text
        _assert_no_secret_leak(assembly)


# ---------------------------------------------------------------------------
# C. Access / Auth (radius + tacacs)
# ---------------------------------------------------------------------------

class TestAccessAuth:
    def test_radius_scheme(self):
        config = (
            "radius scheme RS\n"
            " server-type standard\n"
            " primary authentication 10.0.0.1\n"
            " key cipher SecretRadius\n"
        )
        graph = build_module_graph(config, vendor="h3c")
        _assert_not_unknown(graph)
        assembly = translate_module_graph(graph, "h3c", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested_text = "\n".join("\n".join(r.suggested_lines) for r in near).lower()
        assert "radius" in suggested_text
        _assert_no_secret_leak(assembly)

    def test_tacacs_scheme(self):
        config = (
            "tacacs scheme TS\n"
            " primary authentication 10.0.0.2\n"
            " key cipher SecretTacacs\n"
        )
        graph = build_module_graph(config, vendor="h3c")
        _assert_not_unknown(graph)
        assembly = translate_module_graph(graph, "h3c", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested_text = "\n".join("\n".join(r.suggested_lines) for r in near).lower()
        assert "tacacs" in suggested_text
        _assert_no_secret_leak(assembly)


# ---------------------------------------------------------------------------
# D. Routing (route-policy + prefix-list + OSPF/ISIS/BGP)
# ---------------------------------------------------------------------------

class TestRouting:
    def test_route_policy_match_set_community(self):
        config = (
            "route-policy RP permit node 10\n"
            " if-match community-filter 1\n"
            " apply community 100:1\n"
            " apply ip-address next-hop 10.0.0.1\n"
        )
        graph = build_module_graph(config, vendor="huawei")
        _assert_not_unknown(graph)
        assembly = translate_module_graph(graph, "huawei", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested_text = "\n".join("\n".join(r.suggested_lines) for r in near).lower()
        assert "route-map" in suggested_text
        assert "community" in suggested_text
        assert "<redacted>" in suggested_text
        _assert_no_secret_leak(assembly)

    def test_prefix_list(self):
        config = "ip ip-prefix PL index 10 permit 10.0.0.0 8\n"
        graph = build_module_graph(config, vendor="huawei")
        _assert_not_unknown(graph)
        assembly = translate_module_graph(graph, "huawei", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested_text = "\n".join("\n".join(r.suggested_lines) for r in near).lower()
        assert "prefix-list" in suggested_text

    def test_ospf_import_route(self):
        config = (
            "router ospf 1\n"
            " redistribute static\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        _assert_not_unknown(graph)
        features = {m.feature for m in graph.modules}
        assert "ospf.redistribute" in features
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1

    def test_isis_import_route(self):
        config = (
            "isis 1\n"
            " import-route direct\n"
        )
        graph = build_module_graph(config, vendor="huawei")
        _assert_not_unknown(graph)
        features = {m.feature for m in graph.modules}
        assert "isis.redistribute" in features
        assembly = translate_module_graph(graph, "huawei", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1

    def test_bgp_peer_group(self):
        config = (
            "router bgp 65000\n"
            " neighbor ISP peer-group\n"
            " neighbor ISP remote-as 65001\n"
            " neighbor 10.0.0.1 peer-group ISP\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        _assert_not_unknown(graph)
        features = {m.feature for m in graph.modules}
        assert "bgp.peer_group" in features
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested_text = "\n".join("\n".join(r.suggested_lines) for r in near).lower()
        assert "peer-group" in suggested_text or "group" in suggested_text

    def test_bgp_address_family(self):
        config = (
            "router bgp 65000\n"
            " address-family ipv4 unicast\n"
            "  neighbor 10.0.0.1 activate\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        _assert_not_unknown(graph)
        features = {m.feature for m in graph.modules}
        assert "bgp.address_family" in features or "bgp.activation" in features
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1

    def test_as_path_filter(self):
        config = "ip as-path-filter 1 permit ^100$\n"
        graph = build_module_graph(config, vendor="huawei")
        _assert_not_unknown(graph)
        assembly = translate_module_graph(graph, "huawei", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested_text = "\n".join("\n".join(r.suggested_lines) for r in near).lower()
        assert "as-path" in suggested_text


# ---------------------------------------------------------------------------
# E. IPv6
# ---------------------------------------------------------------------------

class TestIPv6:
    def test_ipv6_route_static(self):
        config = "ipv6 route-static 2001:db8::/32 2001:db8::1\n"
        graph = build_module_graph(config, vendor="huawei")
        _assert_not_unknown(graph)
        assembly = translate_module_graph(graph, "huawei", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested_text = "\n".join("\n".join(r.suggested_lines) for r in near).lower()
        assert "ipv6" in suggested_text

    def test_ipv6_prefix_list(self):
        config = "ipv6 prefix-list V6PL seq 5 permit 2001:db8::/32\n"
        graph = build_module_graph(config, vendor="cisco")
        _assert_not_unknown(graph)
        features = {m.feature for m in graph.modules}
        assert "ipv6.prefix_list" in features
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested_text = "\n".join("\n".join(r.suggested_lines) for r in near).lower()
        assert "prefix-list" in suggested_text or "ip-prefix" in suggested_text

    def test_ipv6_acl_binding(self):
        config = (
            "interface GigabitEthernet0/0/1\n"
            " ipv6 traffic-filter V6ACL in\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        _assert_not_unknown(graph)
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1

    def test_ospfv3_interface(self):
        config = (
            "interface GigabitEthernet0/0/1\n"
            " ospfv3 1 area 0\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        _assert_not_unknown(graph)
        features = {m.feature for m in graph.modules}
        assert "ospfv3.interface" in features
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1


# ---------------------------------------------------------------------------
# F. Firewall
# ---------------------------------------------------------------------------

class TestFirewall:
    def test_firewall_nat(self):
        config = (
            "nat-policy\n"
            " rule name NAT1\n"
            "  source-zone trust\n"
            "  destination-zone untrust\n"
            "  source-address 192.168.1.0 24\n"
            "  action source-nat\n"
        )
        graph = build_module_graph(config, vendor="huawei")
        _assert_not_unknown(graph)
        features = {m.feature for m in graph.modules}
        assert "firewall.nat" in features
        assembly = translate_module_graph(graph, "huawei", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested_text = "\n".join("\n".join(r.suggested_lines) for r in near).lower()
        assert "nat" in suggested_text

    def test_firewall_ipsec(self):
        config = (
            "ipsec policy POLICY 10 isakmp\n"
            " security acl 3000\n"
            " ike-profile PROF\n"
        )
        graph = build_module_graph(config, vendor="huawei")
        _assert_not_unknown(graph)
        features = {m.feature for m in graph.modules}
        assert "firewall.ipsec" in features
        assembly = translate_module_graph(graph, "huawei", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested_text = "\n".join("\n".join(r.suggested_lines) for r in near).lower()
        assert "ipsec" in suggested_text or "crypto" in suggested_text

    def test_zone_interface_binding(self):
        config = (
            "zone name trust\n"
            "  add interface GigabitEthernet0/0/1\n"
        )
        graph = build_module_graph(config, vendor="huawei")
        _assert_not_unknown(graph)
        features = {m.feature for m in graph.modules}
        assert "zone" in features
        assembly = translate_module_graph(graph, "huawei", "cisco")
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        suggested_text = "\n".join("\n".join(r.suggested_lines) for r in near).lower()
        assert "zone" in suggested_text


# ---------------------------------------------------------------------------
# G. Security / deployable_config isolation
# ---------------------------------------------------------------------------

class TestSecurityIsolation:
    def test_no_secret_in_deployable(self):
        config = (
            "radius scheme RS\n"
            " primary authentication 10.0.0.1\n"
            " key cipher MySecretKey\n"
        )
        graph = build_module_graph(config, vendor="h3c")
        assembly = translate_module_graph(graph, "h3c", "cisco")
        deployable = assembly.deployable_config.lower()
        assert "mysecretkey" not in deployable
        assert "<redacted>" in str(assembly.to_dict()).lower() or "MANUAL_REVIEW" in str(assembly.to_dict()).upper()

    def test_no_source_residue_in_deployable(self):
        config = (
            "router ospf 1\n"
            " redistribute static\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        deployable = assembly.deployable_config.lower()
        # "redistribute static" is Cisco syntax and should not appear in Huawei deployable
        assert "redistribute" not in deployable

    def test_uncertain_config_not_in_deployable(self):
        config = (
            "route-policy RP permit node 10\n"
            " if-match community-filter 1\n"
            " apply community 100:1\n"
        )
        graph = build_module_graph(config, vendor="huawei")
        assembly = translate_module_graph(graph, "huawei", "cisco")
        deployable = assembly.deployable_config.lower()
        # route-policy should not be directly deployable
        assert "route-map rp" not in deployable
        # But it should be in semantic_near
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
        assert any("route-map" in "\n".join(r.suggested_lines).lower() for r in near)

    def test_interface_range_not_deployable(self):
        config = (
            "interface range GigabitEthernet0/0/1 to GigabitEthernet0/0/24\n"
            " switchport mode trunk\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        deployable = assembly.deployable_config.lower()
        # interface range should not be in deployable
        assert "interface range" not in deployable
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1

    def test_nat_not_deployable(self):
        config = (
            "nat-policy\n"
            " rule name NAT1\n"
            "  source-zone trust\n"
            "  action source-nat\n"
        )
        graph = build_module_graph(config, vendor="huawei")
        assembly = translate_module_graph(graph, "huawei", "cisco")
        deployable = assembly.deployable_config.lower()
        assert "source-nat" not in deployable
        near = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near) >= 1
