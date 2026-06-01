"""Tests for Batch M module breadth and semantic-near expansion.

Covers:
- interface range classification and semantic-near
- line vty / user-interface classification and semantic-near
- ip dhcp pool classification and semantic-near
- BGP address-family (unicast/multicast) classification and semantic-near
- track object classification and semantic-near
- domain standalone block classification
- broader management.aaa sub-classification (tacacs)
"""
from __future__ import annotations

import pytest

from core.module_graph.builder import build_module_graph
from core.module_graph.translator import translate_module_graph


# ---------------------------------------------------------------------------
# A. Interface range
# ---------------------------------------------------------------------------

class TestInterfaceRange:
    def test_interface_range_classified_not_unknown(self):
        config = "interface range GigabitEthernet0/0/1 to GigabitEthernet0/0/24\n description ACCESS\n"
        graph = build_module_graph(config, vendor="cisco")
        features = {m.feature for m in graph.modules}
        assert "unknown" not in features
        assert any("interface" in f for f in features)

    def test_interface_range_huawei_style(self):
        config = "interface range GigabitEthernet 0/0/1 to 0/0/24\n description SERVERS\n"
        graph = build_module_graph(config, vendor="huawei")
        features = {m.feature for m in graph.modules}
        assert "unknown" not in features

    def test_interface_range_semantic_near(self):
        config = "interface range GigabitEthernet0/0/1 to GigabitEthernet0/0/24\n description ACCESS\n switchport mode access\n"
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near_results = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near_results) >= 1, "interface range should produce semantic_near"
        for r in near_results:
            assert r.suggested_lines, "semantic_near must have suggested_lines"


# ---------------------------------------------------------------------------
# B. Line vty / user-interface
# ---------------------------------------------------------------------------

class TestLineVty:
    def test_line_vty_classified_not_unknown(self):
        config = "line vty 0 4\n transport input ssh\n login local\n"
        graph = build_module_graph(config, vendor="cisco")
        features = {m.feature for m in graph.modules}
        assert "unknown" not in features
        assert any("management" in f or "access" in f for f in features)

    def test_user_interface_classified_not_unknown(self):
        config = "user-interface vty 0 4\n authentication-mode aaa\n protocol inbound ssh\n"
        graph = build_module_graph(config, vendor="huawei")
        features = {m.feature for m in graph.modules}
        assert "unknown" not in features

    def test_line_con_classified_not_unknown(self):
        config = "line con 0\n exec-timeout 10 0\n"
        graph = build_module_graph(config, vendor="cisco")
        features = {m.feature for m in graph.modules}
        assert "unknown" not in features

    def test_line_vty_semantic_near(self):
        config = "line vty 0 4\n transport input ssh\n login local\n"
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near_results = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near_results) >= 1
        for r in near_results:
            assert r.suggested_lines

    def test_user_interface_semantic_near(self):
        config = "user-interface vty 0 4\n authentication-mode aaa\n protocol inbound ssh\n"
        graph = build_module_graph(config, vendor="huawei")
        assembly = translate_module_graph(graph, "huawei", "cisco")
        near_results = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near_results) >= 1


# ---------------------------------------------------------------------------
# C. IP DHCP pool (ip dhcp pool variant)
# ---------------------------------------------------------------------------

class TestIpDhcpPool:
    def test_ip_dhcp_pool_classified(self):
        config = "ip dhcp pool VOICE\n network 10.0.20.0 255.255.255.0\n default-router 10.0.20.1\n"
        graph = build_module_graph(config, vendor="cisco")
        features = {m.feature for m in graph.modules}
        assert "dhcp.pool" in features
        assert "unknown" not in features

    def test_ip_dhcp_pool_semantic_near(self):
        config = "ip dhcp pool VOICE\n network 10.0.20.0 255.255.255.0\n default-router 10.0.20.1\n dns-server 8.8.8.8\n"
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near_results = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near_results) >= 1


# ---------------------------------------------------------------------------
# D. BGP address-family (standard unicast/multicast)
# ---------------------------------------------------------------------------

class TestBgpAddressFamily:
    def test_bgp_address_family_unicast_classified(self):
        config = (
            "router bgp 65000\n"
            " address-family ipv4 unicast\n"
            "  neighbor 10.0.0.2 activate\n"
            "  network 10.10.10.0 mask 255.255.255.0\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        features = {m.feature for m in graph.modules}
        assert "bgp.unknown" not in features or "bgp.address_family" in features
        # At least one bgp feature should not be "unknown"
        bgp_non_unknown = [f for f in features if f.startswith("bgp.") and f != "bgp.unknown"]
        assert len(bgp_non_unknown) >= 1

    def test_bgp_address_family_huawei_style(self):
        config = (
            "bgp 65000\n"
            " ipv4-family unicast\n"
            "  peer 10.0.0.2 enable\n"
            "  network 10.10.10.0 255.255.255.0\n"
        )
        graph = build_module_graph(config, vendor="huawei")
        features = {m.feature for m in graph.modules}
        bgp_non_unknown = [f for f in features if f.startswith("bgp.") and f != "bgp.unknown"]
        assert len(bgp_non_unknown) >= 1

    def test_bgp_address_family_semantic_near(self):
        config = (
            "router bgp 65000\n"
            " address-family ipv4 unicast\n"
            "  neighbor 10.0.0.2 activate\n"
        )
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near_results = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near_results) >= 1


# ---------------------------------------------------------------------------
# E. Track objects
# ---------------------------------------------------------------------------

class TestTrackObject:
    def test_track_classified_not_unknown(self):
        config = "track 1 ip route 10.0.0.0/8 reachability\n"
        graph = build_module_graph(config, vendor="cisco")
        features = {m.feature for m in graph.modules}
        assert "unknown" not in features

    def test_track_huawei_style(self):
        config = "track track1 interface GigabitEthernet0/0/1 line-protocol\n"
        graph = build_module_graph(config, vendor="huawei")
        features = {m.feature for m in graph.modules}
        assert "unknown" not in features

    def test_track_semantic_near(self):
        config = "track 1 ip route 10.0.0.0/8 reachability\n"
        graph = build_module_graph(config, vendor="cisco")
        assembly = translate_module_graph(graph, "cisco", "huawei")
        near_results = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near_results) >= 1


# ---------------------------------------------------------------------------
# F. Domain standalone blocks
# ---------------------------------------------------------------------------

class TestDomainStandalone:
    def test_domain_block_classified_not_unknown(self):
        config = "domain CORP\n authentication lan-access radius-scheme RAD1\n"
        graph = build_module_graph(config, vendor="huawei")
        features = {m.feature for m in graph.modules}
        assert "unknown" not in features

    def test_domain_semantic_near(self):
        config = "domain CORP\n authentication lan-access radius-scheme RAD1\n"
        graph = build_module_graph(config, vendor="huawei")
        assembly = translate_module_graph(graph, "huawei", "cisco")
        near_results = [r for r in assembly.results if r.status == "semantic_near"]
        assert len(near_results) >= 1


# ---------------------------------------------------------------------------
# G. TACACS standalone
# ---------------------------------------------------------------------------

class TestTacacsStandalone:
    def test_tacacs_server_classified_not_unknown(self):
        config = "tacacs-server host 10.0.0.10\n key SECRET\n"
        graph = build_module_graph(config, vendor="cisco")
        features = {m.feature for m in graph.modules}
        assert "unknown" not in features
        assert any("management" in f or "access" in f for f in features)

    def test_tacacs_secret_redacted(self):
        config = "tacacs-server host 10.0.0.10\n key MySecretKey123\n"
        graph = build_module_graph(config, vendor="cisco")
        for module in graph.modules:
            for line in module.source_lines:
                assert "MySecretKey123" not in line, "TACACS key must be redacted"


# ---------------------------------------------------------------------------
# H. No source residue in deployable_config
# ---------------------------------------------------------------------------

class TestNoSourceResidue:
    @pytest.mark.parametrize("config,vendor,target", [
        (
            "interface range GigabitEthernet0/0/1 to GigabitEthernet0/0/24\n switchport mode access\n",
            "cisco", "huawei",
        ),
        (
            "line vty 0 4\n transport input ssh\n login local\n",
            "cisco", "huawei",
        ),
        (
            "user-interface vty 0 4\n authentication-mode aaa\n",
            "huawei", "cisco",
        ),
        (
            "track 1 ip route 10.0.0.0/8 reachability\n",
            "cisco", "huawei",
        ),
    ])
    def test_source_commands_not_in_deployable(self, config, vendor, target):
        graph = build_module_graph(config, vendor=vendor)
        assembly = translate_module_graph(graph, vendor, target)
        deployable = assembly.deployable_config.lower()
        # Source-vendor-specific keywords should not appear in deployable
        source_keywords = _source_vendor_keywords(vendor)
        for kw in source_keywords:
            assert kw not in deployable, f"Source keyword '{kw}' found in deployable_config"


def _source_vendor_keywords(vendor: str) -> list[str]:
    """Return executable keywords specific to the source vendor that should not appear in target."""
    kw = {
        "cisco": ["switchport mode access", "switchport mode trunk", "ip access-group"],
        "huawei": ["port link-type access", "port link-type trunk", "traffic-filter inbound"],
        "h3c": ["port link-type access", "packet-filter inbound"],
    }
    return kw.get(vendor.lower(), [])


# ---------------------------------------------------------------------------
# I. No secret leakage
# ---------------------------------------------------------------------------

class TestNoSecretLeakage:
    @pytest.mark.parametrize("config,vendor,secret", [
        ("tacacs-server host 10.0.0.10\n key SuperSecretKey\n", "cisco", "SuperSecretKey"),
        ("user-interface vty 0 4\n set authentication password cipher SecretPass\n", "huawei", "SecretPass"),
    ])
    def test_secret_not_in_any_output(self, config, vendor, secret):
        graph = build_module_graph(config, vendor=vendor)
        assembly = translate_module_graph(graph, vendor, "cisco" if vendor != "cisco" else "huawei")
        full_output = assembly.deployable_config + "\n" + assembly.manual_review_config
        for r in assembly.results:
            full_output += "\n" + "\n".join(r.suggested_lines)
            full_output += "\n" + "\n".join(r.manual_review_lines)
        assert secret not in full_output, f"Secret '{secret}' leaked in output"
