"""Step 23: Platform Validator Expansion — positive & negative tests."""
import pytest, re

# Reuse the same regex patterns and logic from ValidateNode
from core.graph.nodes import ValidateNode

node = ValidateNode()


# ── Helpers ─────────────────────────────────────────────────────
def _run_validation(config: str, to_vendor: str, source_config: str = "") -> dict:
    """Simulate ValidateNode execution for testing."""
    errors, warnings = node._content_quality_checks(config, to_vendor, source_config)
    pw = node._platform_validation(config, to_vendor)
    result = type("R", (), {"valid": True, "errors": list(errors), "warnings": list(warnings)})()

    critical = node._has_critical_content_warnings(list(warnings) + pw)
    has_critical_residues = any("源厂商残留" in w for w in warnings)
    has_high_risk = bool(pw) or has_critical_residues

    level = "fatal" if len(errors) > 0 else ("warning" if warnings or pw else "info")
    deployable = not (critical or has_critical_residues or level == "fatal")

    return {
        "errors": errors,
        "warnings": warnings + pw,
        "level": level,
        "deployable": deployable,
    }


# ═══════════════════════════════════════════════════════════════════
# POSITIVE TESTS (things that SHOULD be flagged)
# ═══════════════════════════════════════════════════════════════════

class TestCiscoIOSPositive:
    """Cisco IOS target — residues that must set deployable=false."""

    def test_import_route_fatal(self):
        r = _run_validation("router ospf 1\n import-route bgp\n", "cisco")
        assert "import-route" in str(r["warnings"]), "import-route must be flagged"
        assert not r["deployable"], "import-route → deployable=false"

    def test_nat_outbound_fatal(self):
        r = _run_validation("nat outbound 2000\n", "cisco")
        assert "nat outbound" in str(r["warnings"]), "nat outbound must be flagged"
        assert not r["deployable"], "nat outbound → deployable=false"

    def test_security_zone_fatal(self):
        r = _run_validation("security-zone name trust\n", "cisco")
        assert "security-zone" in str(r["warnings"])
        assert not r["deployable"]

    def test_security_policy_fatal(self):
        r = _run_validation("security-policy\n rule name TEST\n action permit\n", "cisco")
        assert "security-policy" in str(r["warnings"])
        assert not r["deployable"]

    def test_huawei_acl_number_fatal(self):
        r = _run_validation("acl number 3000\n rule 0 permit ip source 1.1.1.0 0.0.0.255\n", "cisco")
        assert "acl number" in str(r["warnings"])
        assert not r["deployable"]

    def test_route_policy_fatal(self):
        r = _run_validation("route-policy ALLOW permit node 10\n if-match ip-prefix P1\n apply local-preference 200\n", "cisco")
        assert "route-policy" in str(r["warnings"])
        assert not r["deployable"]

    def test_ip_prefix_fatal(self):
        r = _run_validation("route-policy FILTER permit node 10\n if-match ip-prefix P1\n", "cisco")
        assert "ip-prefix" in str(r["warnings"])

    def test_huawei_undo_shutdown_fatal(self):
        r = _run_validation("interface GigabitEthernet0/0\n undo shutdown\n", "cisco")
        assert "undo shutdown" in str(r["warnings"])

    def test_h3c_port_link_mode_fatal(self):
        r = _run_validation("interface GigabitEthernet0/1\n port link-mode route\n", "cisco")
        assert "port link-mode" in str(r["warnings"])

    def test_info_center_fatal(self):
        r = _run_validation("info-center enable\n", "cisco")
        assert "info-center" in str(r["warnings"])

    def test_local_user_fatal(self):
        r = _run_validation("local-user admin class manage password hash xxx\n", "cisco")
        assert "local-user" in str(r["warnings"])

    def test_reference_missing_prefix_list(self):
        config = """!
route-map BGP-TO-OSPF permit 10
 match ip address prefix-list IMPORT
 set metric 20
!"""
        r = _run_validation(config, "cisco")
        # prefix-list IMPORT is referenced but not defined
        refs = [w for w in r["warnings"] if "未找到定义" in w]
        assert any("prefix-list" in w for w in refs), "undefined prefix-list ref must be flagged"


class TestHuaweiVRPPositive:
    """Huawei VRP target — residues that must set deployable=false."""

    def test_route_map_fatal(self):
        r = _run_validation("route-map RMAP permit 10\n set local-preference 200\n", "huawei")
        assert "route-map" in str(r["warnings"])
        assert not r["deployable"]

    def test_ip_nat_inside_source_fatal(self):
        r = _run_validation("ip nat inside source list 100 interface GigabitEthernet0/0 overload\n", "huawei")
        assert "ip nat inside source" in str(r["warnings"])
        assert not r["deployable"]

    def test_object_group_fatal(self):
        r = _run_validation("object-group network LAN\n network-object 10.0.0.0 255.0.0.0\n", "huawei")
        assert "object-group" in str(r["warnings"])
        assert not r["deployable"]

    def test_access_group_fatal(self):
        r = _run_validation("access-group GLOBAL in interface outside\n", "huawei")
        assert "access-group" in str(r["warnings"])
        assert not r["deployable"]

    def test_reference_missing_route_policy(self):
        config = """#
bgp 65001
 peer 10.0.0.2 route-policy FROM_EBGP import
#"""
        r = _run_validation(config, "huawei")
        refs = [w for w in r["warnings"] if "未找到定义" in w]
        assert any("route-policy" in w for w in refs), "undefined route-policy ref must be flagged"

    def test_reference_missing_ip_prefix(self):
        config = """#
route-policy TEST permit node 10
 if-match ip-prefix NOT_DEFINED
#"""
        r = _run_validation(config, "huawei")
        refs = [w for w in r["warnings"] if "未找到定义" in w]
        assert any("ip-prefix" in w for w in refs), "undefined ip-prefix ref must be flagged"


class TestH3CComwarePositive:
    """H3C Comware target — residues."""

    def test_route_map_fatal(self):
        r = _run_validation("route-map RMAP permit 10\n set community 100:1\n", "h3c")
        assert "route-map" in str(r["warnings"])
        assert not r["deployable"]

    def test_ip_nat_inside_source_fatal(self):
        r = _run_validation("ip nat inside source list 1 pool NATPOOL\n", "h3c")
        assert "ip nat inside source" in str(r["warnings"])
        assert not r["deployable"]

    def test_cisco_channel_group(self):
        r = _run_validation("channel-group 1 mode active\n", "h3c")
        assert "channel-group" in str(r["warnings"])

    def test_cisco_dhcp_pool(self):
        r = _run_validation("ip dhcp pool LAN-POOL\n network 192.168.1.0 255.255.255.0\n", "h3c")
        assert "dhcp pool" in str(r["warnings"])


class TestASAFirewallPositive:
    """ASA target — residues."""

    def test_ios_nat(self):
        r = _run_validation("ip nat inside source list 100 interface outside overload\n", "asa")
        assert any("ip nat" in w for w in r["warnings"]), "IOS NAT must be flagged"
        assert not r["deployable"]

    def test_nat_outbound(self):
        r = _run_validation("nat outbound 2000\n", "asa")
        assert "nat outbound" in str(r["warnings"])

    def test_router_ospf(self):
        r = _run_validation("router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n", "asa")
        assert "router ospf" in str(r["warnings"])

    def test_route_policy_huawei(self):
        r = _run_validation("route-policy FILTER permit node 10\n", "asa")
        assert "route-policy" in str(r["warnings"])


# ═══════════════════════════════════════════════════════════════════
# NEGATIVE TESTS (things that should NOT be flagged)
# ═══════════════════════════════════════════════════════════════════

class TestNoFalsePositives:
    """Platform-appropriate config that should pass cleanly."""

    def test_cisco_ospf_without_import_route(self):
        """Cisco router ospf without import-route — clean."""
        config = """!
router ospf 100
 router-id 1.1.1.1
 network 10.0.0.0 0.0.0.255 area 0
 default-information originate always
!
ip route 0.0.0.0 0.0.0.0 10.0.0.1
!"""
        r = _run_validation(config, "cisco")
        ios_residues = [w for w in r["warnings"] if "源厂商残留" in w]
        assert len(ios_residues) == 0, f"Clean Cisco IOS config flagged: {ios_residues}"

    def test_cisco_bgp_with_route_map(self):
        """Cisco route-map is NATIVE to Cisco — should NOT trigger residue on Cisco target."""
        config = """!
route-map FROM_EBGP permit 10
 match ip address prefix-list IMPORT
 set local-preference 200
!
ip prefix-list IMPORT seq 5 permit 10.0.0.0/8 le 24
!"""
        r = _run_validation(config, "cisco")
        # route-map is native to Cisco, should NOT be flagged
        assert not any("route-map" in w for w in r["warnings"]), "Cisco route-map on Cisco target must not be flagged"

    def test_huawei_route_policy_with_definitions(self):
        """Huawei route-policy with all references defined — clean."""
        config = """#
route-policy FROM_EBGP permit node 10
 if-match ip-prefix IMPORT
 apply local-preference 200
#
ip ip-prefix IMPORT permit 10.0.0.0 8 greater-equal 16 less-equal 24
#
bgp 65001
 peer 10.0.0.2 route-policy FROM_EBGP import
#"""
        r = _run_validation(config, "huawei")
        # route-policy is NATIVE to Huawei — only style-level check
        refs = [w for w in r["warnings"] if "未找到定义" in w]
        assert len(refs) == 0, f"Huawei clean config flagged refs: {refs}"

    def test_ospf_area_consistency(self):
        """OSPF area 0.0.0.18 → area 18 should NOT be flagged."""
        src = """ospf 1
 area 0.0.0.18
  network 10.0.0.0 0.0.0.255
"""
        tgt = """router ospf 1
 network 10.0.0.0 0.0.0.255 area 18
"""
        r = _run_validation(tgt, "cisco", source_config=src)
        area_warnings = [w for w in r["warnings"] if "OSPF area" in w]
        assert len(area_warnings) == 0, f"OSPF area 0.0.0.18 ←→ 18 should not warn: {area_warnings}"

    def test_asa_legitimate_route(self):
        """ASA 'route' command should NOT be flagged as IOS 'ip route'."""
        config = """!
route outside 0.0.0.0 0.0.0.0 203.0.113.254
route inside 10.0.0.0 255.0.0.0 192.168.1.1
!"""
        r = _run_validation(config, "asa")
        # ASA uses 'route' not 'ip route'
        assert not any("ip route" in w.lower() for w in r["warnings"]), "ASA 'route' must not be flagged"

    def test_huawei_nat_server_clean(self):
        """Huawei nat server should not trigger nat outbound residue on huawei."""
        config = """#
interface GigabitEthernet0/0/1
 ip address 203.0.113.1 255.255.255.0
 nat server protocol tcp global 203.0.113.10 443 inside 10.0.0.10 443
#"""
        r = _run_validation(config, "huawei")
        # nat server is native to Huawei
        assert not any("nat outbound" in w for w in r["warnings"]), "Huawei nat server not nat outbound"


# ═══════════════════════════════════════════════════════════════════
# CONSISTENCY CHECK TESTS (Step 37)
# ═══════════════════════════════════════════════════════════════════

class TestConsistencyCheck:
    """_consistency_check: analyzer findings match translated output."""

    def test_nat_analyzer_matches_translated(self):
        """NAT analyzer found NAT → translated has NAT keywords."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "nat", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "ip nat inside source list 1 interface GigabitEthernet0/0 overload"
        warnings, high_risk = node._consistency_check(state, translated)
        assert len(warnings) == 0, f"NAT present but flagged: {warnings}"
        assert not high_risk

    def test_nat_analyzer_mismatch_translated(self):
        """NAT analyzer found NAT → translated missing NAT → warning."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "nat", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0"
        warnings, high_risk = node._consistency_check(state, translated)
        assert any("nat" in w for w in warnings), "Missing NAT in output should warn"
        assert high_risk, "NAT is high-risk → has_high_risk=True"

    def test_lacp_analyzer_matches_translated(self):
        """LACP analyzer → translated has Eth-Trunk."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "lacp", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "interface Eth-Trunk1\n description LACP bundle\n mode lacp"
        warnings, high_risk = node._consistency_check(state, translated)
        assert len(warnings) == 0, f"LACP present but flagged: {warnings}"
        assert not high_risk

    def test_lacp_analyzer_mismatch_translated(self):
        """LACP analyzer → translated missing LACP → warning (no high_risk)."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "lacp", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "interface GigabitEthernet0/0\n no shutdown"
        warnings, high_risk = node._consistency_check(state, translated)
        assert any("lacp" in w for w in warnings), "Missing LACP in output should warn"
        assert not high_risk, "LACP is not high-risk → has_high_risk=False"

    def test_bfd_analyzer_matches_translated(self):
        """BFD analyzer → translated has BFD."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "bfd", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "bfd echo interface GigabitEthernet0/0\n bfd interval 50 min_rx 50 multiplier 3"
        warnings, high_risk = node._consistency_check(state, translated)
        assert len(warnings) == 0, f"BFD present but flagged: {warnings}"
        assert not high_risk

    def test_bfd_analyzer_mismatch_translated(self):
        """BFD analyzer → translated missing BFD → warning."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "bfd", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "router bgp 65001\n network 10.0.0.0 mask 255.0.0.0"
        warnings, high_risk = node._consistency_check(state, translated)
        assert any("bfd" in w for w in warnings), "Missing BFD in output should warn"
        assert not high_risk

    def test_multiple_analyzers_partial_match(self):
        """Two analyzers, only one matches → one warning, no high_risk (qos not in HR set)."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [
                {"feature": "nat", "status": "analyzed", "risk_level": "warning"},
                {"feature": "qos", "status": "analyzed", "risk_level": "warning"},
            ]
        }.get(k, d)})()
        translated = "ip nat inside source list 1 pool POOL overload"
        warnings, high_risk = node._consistency_check(state, translated)
        missing = [w for w in warnings if "consistency" in w]
        features_flagged = [w.split(":")[1].split("]")[0] for w in missing]
        assert "qos" in features_flagged, "Missing QoS should be flagged"
        assert "nat" not in features_flagged, "Present NAT should not be flagged"
        assert not high_risk, "QoS not in HIGH_RISK_CONSISTENCY_FEATURES"

    def test_low_risk_skipped(self):
        """Analyzers with risk_level=none do NOT generate warnings."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "nat", "status": "analyzed", "risk_level": "none"}]
        }.get(k, d)})()
        translated = "interface GigabitEthernet0/0\n no shutdown"
        warnings, high_risk = node._consistency_check(state, translated)
        assert len(warnings) == 0, "Low-risk analyzers should be skipped"
        assert not high_risk

    def test_unknown_feature_skipped(self):
        """Features not in FEATURE_OUTPUT_PATTERNS are skipped cleanly."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "unknown_xyz", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "any config here"
        warnings, high_risk = node._consistency_check(state, translated)
        assert len(warnings) == 0, "Unknown features should be skipped"
        assert not high_risk

    def test_no_analyzer_results(self):
        """No analyzer_results in state → no warnings."""
        state = type("S", (), {"get": lambda s, k, d=None: {}.get(k, d)})()
        translated = "any config here"
        warnings, high_risk = node._consistency_check(state, translated)
        assert len(warnings) == 0, "No analyzers → no warnings"
        assert not high_risk

    def test_no_status_field(self):
        """Missing status field gracefully handled (not 'analyzed' → skipped)."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "nat", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "interface GigabitEthernet0/0\n no shutdown"
        warnings, high_risk = node._consistency_check(state, translated)
        assert len(warnings) == 0, "Missing status key → should be skipped"
        assert not high_risk

    def test_empty_analyzer_results_list(self):
        """Empty analyzer_results list → no warnings."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": []
        }.get(k, d)})()
        translated = "any config here"
        warnings, high_risk = node._consistency_check(state, translated)
        assert len(warnings) == 0, "Empty list → no warnings"
        assert not high_risk

    def test_analyzer_results_as_dict_legacy(self):
        """Legacy dict format for analyzer_results still works."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": {"nat": {"feature": "nat", "status": "analyzed", "risk_level": "warning"}}
        }.get(k, d)})()
        translated = "ip nat inside source list 1 pool POOL overload"
        warnings, high_risk = node._consistency_check(state, translated)
        assert len(warnings) == 0, "Dict format should still work"
        assert not high_risk

    def test_stp_analyzer_matches_translated(self):
        """STP analyzer → translated has spanning-tree."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "stp", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "spanning-tree mode rapid-pvst\n spanning-tree vlan 100 priority 4096"
        warnings, high_risk = node._consistency_check(state, translated)
        assert len(warnings) == 0, f"STP present but flagged: {warnings}"
        assert not high_risk

    def test_vrf_analyzer_matches_translated(self):
        """VRF analyzer → translated has vrf forwarding."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "vrf", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "vrf definition CUSTOMER\n rd 100:1\n !\n interface GigabitEthernet0/0\n vrf forwarding CUSTOMER"
        warnings, high_risk = node._consistency_check(state, translated)
        assert len(warnings) == 0, f"VRF present but flagged: {warnings}"
        assert not high_risk

    def test_security_policy_mismatch_high_risk(self):
        """Security-policy missing from output → high_risk=True."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "security_policy", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "interface GigabitEthernet0/0\n no shutdown"
        warnings, high_risk = node._consistency_check(state, translated)
        assert any("security_policy" in w for w in warnings)
        assert high_risk, "security_policy is high-risk → has_high_risk=True"

    def test_ipsec_mismatch_high_risk(self):
        """IPsec missing from output → high_risk=True."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "ipsec", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "interface GigabitEthernet0/0\n no shutdown"
        warnings, high_risk = node._consistency_check(state, translated)
        assert high_risk, "ipsec is high-risk → has_high_risk=True"

    def test_acl_mismatch_high_risk(self):
        """ACL missing from output → high_risk=True."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "acl", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "interface GigabitEthernet0/0\n no shutdown"
        warnings, high_risk = node._consistency_check(state, translated)
        assert high_risk, "acl is high-risk → has_high_risk=True"

    def test_route_policy_mismatch_high_risk(self):
        """Route-policy missing from output → high_risk=True."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "route_policy", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "interface GigabitEthernet0/0\n no shutdown"
        warnings, high_risk = node._consistency_check(state, translated)
        assert high_risk, "route_policy is high-risk → has_high_risk=True"

    def test_high_risk_with_manual_review_no_high_risk(self):
        """MANUAL_REVIEW in output suppresses high_risk flag."""
        state = type("S", (), {"get": lambda s, k, d=None: {
            "analyzer_results": [{"feature": "nat", "status": "analyzed", "risk_level": "warning"}]
        }.get(k, d)})()
        translated = "MANUAL_REVIEW: NAT translation requires manual configuration\n no ip nat inside source"
        warnings, high_risk = node._consistency_check(state, translated)
        assert len(warnings) == 0, "MANUAL_REVIEW suppresses warning"
        assert not high_risk


# ═══════════════════════════════════════════════════════════════════
# STEP 38: Platform Validator Deepening
# ═══════════════════════════════════════════════════════════════════

class TestPlatformValidatorCiscoResidue:
    """Cisco IOS target — new deep residue patterns."""

    def test_asa_object_network(self):
        r = _run_validation("object network LAN\n subnet 10.0.0.0 255.0.0.0\n", "cisco")
        assert all("源厂商残留" not in w for w in r["warnings"]), "object network is valid Cisco command"
        assert r["deployable"]

    def test_asa_object_group(self):
        r = _run_validation("object-group network LAN\n network-object 10.0.0.0 255.0.0.0\n", "cisco")
        assert all("object-group" not in w for w in r["warnings"]), "object-group is valid Cisco command"

    def test_asa_access_group(self):
        r = _run_validation("access-group OUTSIDE in interface outside\n", "cisco")
        assert not any("源厂商残留" in w for w in r["warnings"]), "access-group is valid Cisco command, not a residue"

    def test_huawei_security_zone(self):
        r = _run_validation("security-zone name trust\n zone-pair security source trust destination untrust\n", "cisco")
        assert any("security-zone" in w for w in r["warnings"])

    def test_huawei_security_policy(self):
        r = _run_validation("security-policy\n rule name PERMIT\n action permit\n", "cisco")
        assert any("security-policy" in w for w in r["warnings"])
        assert not r["deployable"]

    def test_huawei_route_policy(self):
        r = _run_validation("route-policy ALLOW permit node 10\n if-match ip-prefix P1\n apply local-preference 200\n", "cisco")
        assert any("route-policy" in w for w in r["warnings"])

    def test_huawei_ip_ip_prefix(self):
        r = _run_validation("ip ip-prefix P1 permit 10.0.0.0 8 greater-equal 16\n", "cisco")
        assert any("ip-prefix" in w for w in r["warnings"])

    def test_huawei_import_route(self):
        r = _run_validation("router ospf 1\n import-route bgp\n", "cisco")
        assert any("import-route" in w for w in r["warnings"])

    def test_huawei_nat_outbound(self):
        r = _run_validation("nat outbound 2000\n", "cisco")
        assert any("nat outbound" in w for w in r["warnings"])

    def test_huawei_info_center(self):
        r = _run_validation("info-center enable\n", "cisco")
        assert any("info-center" in w for w in r["warnings"])

    def test_huawei_local_user(self):
        r = _run_validation("local-user admin class manage password hash xxx\n", "cisco")
        assert any("local-user" in w for w in r["warnings"])

    def test_huawei_undo_shutdown(self):
        r = _run_validation("interface GigabitEthernet0/0\n undo shutdown\n", "cisco")
        assert any("undo shutdown" in w for w in r["warnings"])

    def test_h3c_port_link_mode(self):
        r = _run_validation("interface GigabitEthernet0/1\n port link-mode route\n", "cisco")
        assert any("port link-mode" in w for w in r["warnings"])

    def test_aclnumber_in_cisco(self):
        r = _run_validation("acl number 3000\n rule 0 permit ip source 1.1.1.0 0.0.0.255\n", "cisco")
        assert any("acl number" in w for w in r["warnings"])

    def test_cisco_bfd_syntax_not_false_positive(self):
        r = _run_validation("interface GigabitEthernet0/0\n ip ospf bfd\n bfd interval 100\n", "cisco")
        assert not any("bfd" in w for w in r["warnings"]), "Cisco BFD syntax should not trigger residue"


class TestPlatformValidatorHuaweiResidue:
    """Huawei VRP target — new deep residue patterns."""

    def test_cisco_route_map(self):
        r = _run_validation("route-map RMAP permit 10\n set metric 20\n", "huawei")
        assert any("route-map" in w for w in r["warnings"])
        assert not r["deployable"]

    def test_cisco_ip_prefix_list(self):
        r = _run_validation("ip prefix-list P1 seq 5 permit 10.0.0.0/8\n", "huawei")
        assert any("prefix-list" in w for w in r["warnings"])

    def test_cisco_ip_nat_inside_source(self):
        r = _run_validation("ip nat inside source list 100 interface GigabitEthernet0/0 overload\n", "huawei")
        assert any("nat inside" in w for w in r["warnings"])

    def test_cisco_access_group(self):
        r = _run_validation("access-group OUT in interface outside\n", "huawei")
        assert any("access-group" in w for w in r["warnings"])

    def test_cisco_object_network(self):
        r = _run_validation("object network LAN\n subnet 10.0.0.0 255.0.0.0\n", "huawei")
        assert any("object network" in w for w in r["warnings"])

    def test_cisco_channel_group(self):
        r = _run_validation("interface Port-channel1\n channel-group 1 mode active\n", "huawei")
        assert any("channel-group" in w for w in r["warnings"])

    def test_cisco_ip_dhcp_pool(self):
        r = _run_validation("ip dhcp pool LAN-POOL\n network 192.168.1.0 255.255.255.0\n", "huawei")
        assert any("dhcp pool" in w for w in r["warnings"])

    def test_cisco_default_information_originate(self):
        r = _run_validation("router bgp 65001\n default-information originate\n", "huawei")
        assert any("default-information" in w for w in r["warnings"])

    def test_cisco_router_ospf(self):
        r = _run_validation("router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n", "huawei")
        assert any("Cisco" in w for w in r["warnings"])

    def test_cisco_standby(self):
        r = _run_validation("interface Vlan100\n standby 10 ip 10.0.0.254\n", "huawei")
        assert any("standby" in w for w in r["warnings"])

    def test_cisco_no_shutdown(self):
        r = _run_validation("interface GigabitEthernet0/0\n no shutdown\n", "huawei")
        assert any("no shutdown" in w for w in r["warnings"])

    def test_cisco_object_group_in_huawei(self):
        r = _run_validation("object-group network LAN\n network-object 10.0.0.0 255.0.0.0\n", "huawei")
        assert any("object-group" in w for w in r["warnings"])

    def test_asa_nameif_in_vrp(self):
        r = _run_validation("interface GigabitEthernet0/0\n nameif inside\n security-level 100\n", "huawei")
        assert not r["deployable"]
        assert any("nameif" in w.lower() or "security-level" in w.lower() for w in r["warnings"])

    def test_asa_security_level_in_vrp(self):
        r = _run_validation("security-level 50\n", "huawei")
        assert any("security-level" in w.lower() for w in r["warnings"])


class TestPlatformValidatorH3CResidue:
    """H3C Comware target — new deep residue patterns."""

    def test_cisco_route_map(self):
        r = _run_validation("route-map RMAP permit 10\n set metric 20\n", "h3c")
        assert any("route-map" in w for w in r["warnings"])
        assert not r["deployable"]

    def test_cisco_ip_prefix_list(self):
        r = _run_validation("ip prefix-list P1 seq 5 permit 10.0.0.0/8\n", "h3c")
        assert any("prefix-list" in w for w in r["warnings"])

    def test_cisco_ip_nat_inside_source(self):
        r = _run_validation("ip nat inside source list 100 interface GigabitEthernet0/0 overload\n", "h3c")
        assert any("nat inside" in w for w in r["warnings"])

    def test_cisco_channel_group(self):
        r = _run_validation("channel-group 1 mode active\n", "h3c")
        assert any("channel-group" in w for w in r["warnings"])

    def test_cisco_no_shutdown(self):
        r = _run_validation("interface GigabitEthernet0/0\n no shutdown\n", "h3c")
        assert any("no shutdown" in w for w in r["warnings"])

    def test_cisco_ip_dhcp_pool(self):
        r = _run_validation("ip dhcp pool LAN-POOL\n network 192.168.1.0 255.255.255.0\n", "h3c")
        assert any("dhcp pool" in w for w in r["warnings"])


class TestPlatformValidatorASAResidue:
    """ASA target — new deep residue patterns."""

    def test_ios_router_ospf(self):
        r = _run_validation("router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n", "asa")
        assert any("router ospf" in w for w in r["warnings"])
        assert not r["deployable"]

    def test_ios_router_bgp(self):
        r = _run_validation("router bgp 65001\n", "asa")
        assert any("router bgp" in w for w in r["warnings"])

    def test_ios_ip_nat_inside_source(self):
        r = _run_validation("ip nat inside source list 100 interface outside overload\n", "asa")
        assert any("nat inside" in w for w in r["warnings"])

    def test_ios_ip_route(self):
        r = _run_validation("ip route 0.0.0.0 0.0.0.0 10.0.0.1\n", "asa")
        assert any("ip route" in w for w in r["warnings"])

    def test_ios_route_map(self):
        r = _run_validation("route-map RMAP permit 10\n set metric 20\n", "asa")
        assert any("route-map" in w for w in r["warnings"])

    def test_huawei_security_zone(self):
        r = _run_validation("security-zone name trust\n", "asa")
        assert any("security-zone" in w for w in r["warnings"])

    def test_huawei_route_policy(self):
        r = _run_validation("route-policy ALLOW permit node 10\n", "asa")
        assert any("route-policy" in w for w in r["warnings"])

    def test_undo_shutdown(self):
        r = _run_validation("interface GigabitEthernet0/0\n undo shutdown\n", "asa")
        assert any("undo shutdown" in w for w in r["warnings"])

    def test_ios_prefix_list(self):
        r = _run_validation("ip prefix-list P1 seq 5 permit 10.0.0.0/8\n", "asa")
        assert any("prefix-list" in w for w in r["warnings"])


class TestPlatformValidatorStructure:
    """Structure checks — ACL number, VRF format, interface naming."""

    def test_huawei_acl_out_of_range(self):
        r = _run_validation("acl number 5000\n rule 0 permit ip\n", "huawei")
        assert any("ACL number" in w for w in r["warnings"]), "5000 out of Huawei ACL range"

    def test_huawei_acl_2000_in_range(self):
        r = _run_validation("acl number 2000\n rule 0 permit\n", "huawei")
        assert not any("ACL number" in w for w in r["warnings"]), "2000 is valid basic ACL"

    def test_huawei_acl_3000_in_range(self):
        r = _run_validation("acl number 3000\n rule 0 permit ip\n", "huawei")
        assert not any("ACL number" in w for w in r["warnings"]), "3000 is valid advanced ACL"

    def test_h3c_acl_out_of_range(self):
        r = _run_validation("acl number 5000\n rule 0 permit ip\n", "h3c")
        assert any("ACL number" in w for w in r["warnings"]), "5000 out of H3C ACL range"

    def test_cisco_vrf_rd_missing_colon(self):
        r = _run_validation("vrf definition CUSTOMER\n rd 1001001\n", "cisco")
        assert any("缺少冒号" in w for w in r["warnings"]), "RD without colon should warn"

    def test_cisco_vrf_rd_valid(self):
        r = _run_validation("vrf definition CUSTOMER\n rd 100:1\n", "cisco")
        assert not any("route-target" in w for w in r["warnings"]), "RD with colon is valid"

    def test_cisco_vrf_rt_missing_colon(self):
        r = _run_validation("vrf definition CUSTOMER\n route-target export 1001001\n", "cisco")
        assert any("缺少冒号" in w for w in r["warnings"])

    def test_huawei_interface_mixed_types(self):
        r = _run_validation("interface GigabitEthernet0/0/1\n ip address 10.0.0.1 255.0.0.0\n interface Ethernet0/0/2\n ip address 10.0.0.2 255.0.0.0\n", "huawei")
        assert any("接口类型混用" in w for w in r["warnings"])


class TestPlatformValidatorReferences:
    """Reference relationship checks — new patterns."""

    def test_asa_object_group_reference_missing(self):
        config = """object-group network LAN
 network-object 10.0.0.0 255.0.0.0
!
access-group LAN in interface outside"""
        r = _run_validation(config, "asa")
        refs = [w for w in r["warnings"] if "未找到定义" in w]
        assert any("object-group" in w for w in refs), "ASA object-group ref must be checked"

    def test_asa_object_network_reference(self):
        config = """object network MY_NET
 subnet 10.0.0.0 255.0.0.0
!
nat (inside,outside) source dynamic MY_NET interface"""
        r = _run_validation(config, "asa")
        refs = [w for w in r["warnings"] if "未找到定义" in w]
        assert not any("MY_NET" in w for w in refs), "MY_NET is defined (object network)"

    def test_cisco_access_group_reference_missing(self):
        config = """!
access-group MY_ACL in
!"""
        r = _run_validation(config, "cisco")
        refs = [w for w in r["warnings"] if "未找到定义" in w]
        assert any("MY_ACL" in w for w in refs), "undefined access-list in access-group"

    def test_cisco_access_group_reference_valid(self):
        config = """access-list 100 permit ip 10.0.0.0 0.0.0.255 any
!
access-group 100 in"""
        r = _run_validation(config, "cisco")
        refs = [w for w in r["warnings"] if "未找到定义" in w]
        assert not any("100" in w for w in refs), "access-list 100 is defined"

    def test_h3c_route_policy_reference_missing(self):
        config = """#
bgp 65001
 peer 10.0.0.2 route-policy FROM_EBGP import
#"""
        r = _run_validation(config, "h3c")
        refs = [w for w in r["warnings"] if "未找到定义" in w]
        assert any("route-policy" in w for w in refs), "H3C undefined route-policy ref"

    def test_h3c_route_policy_reference_valid(self):
        config = """#
route-policy FROM_EBGP permit node 10
 if-match ip-prefix IMPORT
#
ip ip-prefix IMPORT permit 10.0.0.0 8 greater-equal 16 less-equal 24
#
bgp 65001
 peer 10.0.0.2 route-policy FROM_EBGP import
#"""
        r = _run_validation(config, "h3c")
        refs = [w for w in r["warnings"] if "未找到定义" in w]
        assert not any("route-policy" in w for w in refs), "H3C route-policy FROM_EBGP is defined"


class TestPlatformValidatorNoFalsePositives:
    """Platform-appropriate config that should NOT trigger new residues."""

    def test_cisco_native_route_map(self):
        r = _run_validation("route-map RMAP permit 10\n match ip address prefix-list P1\n set metric 20\n!", "cisco")
        ios_residues = [w for w in r["warnings"] if "源厂商残留" in w]
        assert len(ios_residues) == 0, f"Cisco route-map on Cisco flagged: {ios_residues}"

    def test_cisco_native_access_list(self):
        r = _run_validation("access-list 100 permit ip 10.0.0.0 0.0.0.255 any\n!", "cisco")
        ios_residues = [w for w in r["warnings"] if "源厂商残留" in w]
        assert len(ios_residues) == 0, f"Cisco access-list on Cisco flagged: {ios_residues}"

    def test_huawei_native_route_policy(self):
        r = _run_validation("route-policy ALLOW permit node 10\n if-match ip-prefix P1\n apply local-preference 200\n#", "huawei")
        residues = [w for w in r["warnings"] if "源厂商残留" in w]
        assert len(residues) == 0, f"Huawei route-policy on Huawei flagged: {residues}"

    def test_huawei_native_nat_server(self):
        r = _run_validation("interface GigabitEthernet0/0/1\n ip address 203.0.113.1 255.255.255.0\n nat server protocol tcp global 203.0.113.10 443 inside 10.0.0.10 443\n#", "huawei")
        residues = [w for w in r["warnings"] if "源厂商残留" in w]
        assert len(residues) == 0, f"Huawei nat server flagged as residue: {residues}"

    def test_h3c_native_route_policy(self):
        r = _run_validation("route-policy ALLOW permit node 10\n if-match ip-prefix P1\n apply local-preference 200\n#", "h3c")
        residues = [w for w in r["warnings"] if "源厂商残留" in w]
        assert len(residues) == 0, f"H3C route-policy on H3C flagged: {residues}"

    def test_asa_native_nat(self):
        r = _run_validation("nat (inside,outside) source dynamic interface\n!", "asa")
        residues = [w for w in r["warnings"] if "源厂商残留" in w]
        assert len(residues) == 0, f"ASA native nat flagged as residue: {residues}"

    def test_cisco_vrf_rd_with_colon(self):
        r = _run_validation("vrf definition CUSTOMER\n rd 100:1\n route-target export 100:1\n route-target import 100:1\n!", "cisco")
        rd_issues = [w for w in r["warnings"] if "缺少冒号" in w]
        assert len(rd_issues) == 0, f"Valid RD/RT flagged: {rd_issues}"

    def test_cisco_vrf_format_check_only_matches_executable_vrf_lines(self):
        config = """! MANUAL_REVIEW unsupported source command: password history record number 0
! MANUAL_REVIEW unsupported source command: local-user admin password irreversible-cipher x
hostname SW1
"""
        r = _run_validation(config, "cisco")
        rd_issues = [w for w in r["warnings"] if "VRF RD/route-target 格式异常" in w]
        residues = [w for w in r["warnings"] if "源厂商残留" in w]
        assert rd_issues == [], f"Comment text should not trigger VRF RD/RT warnings: {rd_issues}"
        assert residues == [], f"MANUAL_REVIEW comments should not count as executable residue: {residues}"

    def test_cisco_executable_vrf_rd_without_colon_still_warns(self):
        r = _run_validation("vrf definition CUSTOMER\n rd 1001001\n", "cisco")
        assert any("VRF RD/route-target 格式异常" in w for w in r["warnings"])

    def test_cisco_named_ip_access_list_satisfies_access_group_reference(self):
        config = """ip access-list extended D-ACL-OA
 10 permit ip any any
interface Vlan10
 ip access-group D-ACL-OA out
"""
        r = _run_validation(config, "cisco")
        ref_issues = [w for w in r["warnings"] if "access-list D-ACL-OA 在 access-group 中被引用但未找到定义" in w]
        assert ref_issues == [], f"Named ACL definition should satisfy access-group reference: {ref_issues}"

    def test_huawei_valid_acl_range(self):
        r = _run_validation("acl number 3000\n rule 0 permit ip source 10.0.0.0 0.0.0.255 destination any\n#", "huawei")
        acl_issues = [w for w in r["warnings"] if "ACL number" in w]
        assert len(acl_issues) == 0, f"Valid ACL 3000 flagged: {acl_issues}"

    def test_huawei_ike_proposal_not_residue(self):
        r = _run_validation("ike proposal 10\n authentication-algorithm sha1\n encryption-algorithm aes-256\n dh group2\n sa duration 86400\n#", "huawei")
        residues = [w for w in r["warnings"] if "源厂商残留" in w]
        assert len(residues) == 0, f"Huawei IKE proposal flagged as residue: {residues}"

    def test_huawei_ip_address_set_not_residue(self):
        r = _run_validation("ip address-set LAN_SERVERS type object\n address 0 10.0.0.10 255.255.255.255\n#", "huawei")
        residues = [w for w in r["warnings"] if "源厂商残留" in w]
        assert len(residues) == 0, f"Huawei ip address-set flagged as residue: {residues}"

    def test_huawei_firewall_zone_not_residue(self):
        r = _run_validation("firewall zone trust\n set priority 85\n add interface GigabitEthernet0/0/0\n#", "huawei")
        residues = [w for w in r["warnings"] if "源厂商残留" in w]
        assert len(residues) == 0, f"Huawei firewall zone flagged as residue: {residues}"

    def test_huawei_packet_filter_not_residue(self):
        r = _run_validation("interface GigabitEthernet0/0/1\n packet-filter 3000 inbound\n#", "huawei")
        residues = [w for w in r["warnings"] if "源厂商残留" in w]
        assert len(residues) == 0, f"Huawei packet-filter flagged as residue: {residues}"


class TestNewDeployabilityModel:
    """P0-1: High-risk feature presence alone does NOT force deployable=false."""

    def test_high_risk_feature_clean_no_risk(self):
        """nat present but no analyzer/validator/consistency risk → deployable=true."""
        dep = node._evaluate_deployability(
            validation_level="info",
            high_risk_warning=False,
            critical_content_warning=False,
            features=["nat"],
        )
        assert dep["deployable"], "nat alone without risk should be deployable"
        assert not dep["manual_review_required"], "nat alone should not force manual review"

    def test_high_risk_feature_with_warning(self):
        """nat present + high_risk_warning=true → deployable=false."""
        dep = node._evaluate_deployability(
            validation_level="warning",
            high_risk_warning=True,
            critical_content_warning=False,
            features=["nat"],
        )
        assert not dep["deployable"], "nat with high_risk_warning: deployable=false"
        assert dep["manual_review_required"], "nat with high_risk_warning: manual review"

    def test_high_risk_feature_with_critical_content(self):
        """nat present + critical_content_warning=true → deployable=false."""
        dep = node._evaluate_deployability(
            validation_level="warning",
            high_risk_warning=False,
            critical_content_warning=True,
            features=["nat"],
        )
        assert not dep["deployable"], "nat with critical content: deployable=false"
        assert dep["manual_review_required"], "nat with critical content: manual review"

    def test_high_risk_feature_fatal_level(self):
        """validation_level=fatal → deployable=false regardless of features."""
        dep = node._evaluate_deployability(
            validation_level="fatal",
            high_risk_warning=False,
            critical_content_warning=False,
            features=["nat"],
        )
        assert not dep["deployable"], "fatal level: deployable=false"
        assert dep["manual_review_required"], "fatal level: manual review"

    def test_non_high_risk_warning(self):
        """warning level without high_risk → deployable=true, manual_review=true."""
        dep = node._evaluate_deployability(
            validation_level="warning",
            high_risk_warning=False,
            critical_content_warning=False,
            features=[],
        )
        assert dep["deployable"], "ordinary warning: deployable=true"
        assert dep["manual_review_required"], "ordinary warning: manual review"

    def test_detect_features_from_config_includes_route_policy(self):
        """rtr-bgp-001 source config must yield route_policy in detected features."""
        from tools.knowledge_manager import detect_features_from_config
        bgp_config = """!
router bgp 65001
 neighbor 198.18.1.2 route-map PREFER_ISP1 in
 neighbor 198.18.1.2 prefix-list CUSTOMER_PREFIXES out
!
ip prefix-list CUSTOMER_PREFIXES seq 5 permit 198.18.0.0/16
!
route-map PREFER_ISP1 permit 10
 match ip address prefix-list CUSTOMER_PREFIXES
 set local-preference 150
!
route-map PREFER_ISP1 permit 20
 set local-preference 100
!"""
        features = detect_features_from_config(bgp_config)
        assert "route_policy" in features, f"route_policy must be detected, got {features}"
        assert "bgp" in features
        assert "pbr" in features


class TestBgpPolicyRefs:
    """P1-4: BGP route-policy/prefix-list cross-references must be preserved."""

    def test_cisco_neighbor_route_map_missing_in_huawei_target(self):
        """Cisco BGP neighbor route-map → Huawei target missing route-policy → warning."""
        source = """!
router bgp 65001
 neighbor 198.18.1.2 route-map PREFER_ISP1 in
!"""
        target = """bgp 65001
 peer 198.18.1.2 as-number 65001
!"""
        warnings = node._check_bgp_policy_refs(source, target, "huawei")
        assert len(warnings) > 0, "Missing route-policy should be flagged"
        assert any("PREFER_ISP1" in w for w in warnings)

    def test_cisco_neighbor_prefix_list_missing_in_huawei_target(self):
        """Cisco BGP neighbor prefix-list → Huawei target missing ip-prefix → warning."""
        source = """!
router bgp 65001
 neighbor 198.18.1.2 prefix-list CUSTOMER_PREFIXES out
!"""
        target = """bgp 65001
 peer 198.18.1.2 as-number 65001
!"""
        warnings = node._check_bgp_policy_refs(source, target, "huawei")
        assert len(warnings) > 0
        assert any("CUSTOMER_PREFIXES" in w for w in warnings)

    def test_huawei_peer_route_policy_missing_in_cisco_target(self):
        """Huawei BGP peer route-policy → Cisco target missing route-map → warning."""
        source = """#
bgp 65001
 peer 10.0.0.2 route-policy FROM_EBGP import
#"""
        target = """!
router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
!"""
        warnings = node._check_bgp_policy_refs(source, target, "cisco")
        assert len(warnings) > 0
        assert any("FROM_EBGP" in w for w in warnings)

    def test_bgp_policy_defined_in_huawei_target_no_warning(self):
        """Source has route-map ref, Huawei target has route-policy defined → OK."""
        source = """!
router bgp 65001
 neighbor 198.18.1.2 route-map PREFER_ISP1 in
 neighbor 198.18.1.2 prefix-list CUSTOMER_PREFIXES out
!"""
        target = """bgp 65001
 peer 198.18.1.2 as-number 65001
 peer 198.18.1.2 route-policy PREFER_ISP1 import
!
route-policy PREFER_ISP1 permit node 10
 apply local-preference 150
!
ip ip-prefix CUSTOMER_PREFIXES permit 198.18.0.0 16
!"""
        warnings = node._check_bgp_policy_refs(source, target, "huawei")
        assert len(warnings) == 0, f"All refs present but got warnings: {warnings}"

    def test_bgp_policy_defined_in_cisco_target_no_warning(self):
        """Source has route-policy ref, Cisco target has route-map defined → OK."""
        source = """#
bgp 65001
 peer 10.0.0.2 route-policy FROM_EBGP import
 peer 10.0.0.2 ip-prefix PREFIXES export
#"""
        target = """!
router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
 neighbor 10.0.0.2 route-map FROM_EBGP in
 neighbor 10.0.0.2 prefix-list PREFIXES out
!
route-map FROM_EBGP permit 10
 set local-preference 200
!
ip prefix-list PREFIXES seq 5 permit 10.0.0.0/8
!"""
        warnings = node._check_bgp_policy_refs(source, target, "cisco")
        assert len(warnings) == 0, f"All refs present but got warnings: {warnings}"

    def test_bgp_policy_manual_review_flagged(self):
        """Target has MANUAL_REVIEW for BGP policy → flagged but allowed."""
        source = """!
router bgp 65001
 neighbor 198.18.1.2 route-map PREFER_ISP1 in
!"""
        target = """! MANUAL_REVIEW: route-policy needs manual config
bgp 65001
 peer 198.18.1.2 as-number 65001
!"""
        warnings = node._check_bgp_policy_refs(source, target, "huawei")
        assert len(warnings) > 0, "MANUAL_REVIEW should still produce warning"
        assert any("MANUAL_REVIEW" in w for w in warnings) or any("PREFER_ISP1" in w for w in warnings)

    def test_no_bgp_policy_in_source_no_warning(self):
        """Source without BGP policy refs → no warning."""
        source = """!
router bgp 65001
 neighbor 198.18.1.2 remote-as 65002
 network 10.0.0.0
!"""
        target = """bgp 65001
 peer 198.18.1.2 as-number 65002
 network 10.0.0.0
!"""
        warnings = node._check_bgp_policy_refs(source, target, "huawei")
        assert len(warnings) == 0


class TestStpRootRole:
    """P1-3: STP root primary/root secondary/priority semantics must be preserved."""

    def test_stp_root_primary_missing_flagged(self):
        """Source has root primary, target lacks it → warning."""
        source = """!
spanning-tree mode mst
spanning-tree mst configuration
 name LAB
 instance 1 vlan 10,20
!
spanning-tree mst 1 root primary
!"""
        target = """stp mode mstp
stp region-configuration
 region-name LAB
 instance 1 vlan 10 20
 active region-configuration
!"""
        warnings = node._check_stp_root_role(source, target)
        assert len(warnings) > 0, "Missing root primary should be flagged"
        assert any("STP root role" in w for w in warnings), "Warning should mention STP root role"

    def test_stp_root_primary_present_no_warning(self):
        """Source has root primary, target has root primary → no warning."""
        source = """!
spanning-tree mst 1 root primary
!"""
        target = """stp instance 1 root primary"""
        warnings = node._check_stp_root_role(source, target)
        assert len(warnings) == 0, f"root primary present but got warnings: {warnings}"

    def test_stp_root_primary_with_priority_no_warning(self):
        """Source has root primary, target has equivalent priority → no warning."""
        source = """!
spanning-tree mst 1 root primary
!"""
        target = """stp instance 1 priority 24576"""
        warnings = node._check_stp_root_role(source, target)
        assert len(warnings) == 0, f"priority 24576 present but got warnings: {warnings}"

    def test_stp_root_secondary_in_target_no_warning(self):
        """Source has root secondary, target has root secondary → no warning."""
        source = """!
spanning-tree mst 2 root secondary
!"""
        target = """stp instance 2 root secondary"""
        warnings = node._check_stp_root_role(source, target)
        assert len(warnings) == 0

    def test_stp_manual_review_suppresses_warning(self):
        """Source has root primary, target has MANUAL_REVIEW → no warning."""
        source = """!
spanning-tree mst 1 root primary
!"""
        target = """! MANUAL_REVIEW: MST root role requires manual config"""
        warnings = node._check_stp_root_role(source, target)
        assert len(warnings) == 0, f"MANUAL_REVIEW present but got warnings: {warnings}"

    def test_stp_no_root_role_in_source_no_warning(self):
        """Source without STP root role → no warning."""
        source = """!
spanning-tree mode mst
spanning-tree mst configuration
 name LAB
 instance 1 vlan 10,20
!"""
        target = """stp mode mstp
stp region-configuration
 region-name LAB
 instance 1 vlan 10 20
 active region-configuration
!"""
        warnings = node._check_stp_root_role(source, target)
        assert len(warnings) == 0, f"No root role in source but got warnings: {warnings}"
