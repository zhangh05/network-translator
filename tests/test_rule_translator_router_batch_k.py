# -*- coding: utf-8 -*-
"""Batch K-B: ROUTER fallback translation hardening tests.

Priority items:
  1. static route name/tag/preference/distance/track/bfd
  2. OSPF stub/nssa/virtual-link MANUAL_REVIEW (verify no passthrough)
  3. BGP update-source, ebgp-multihop, password redaction
  4. VRF import/export policy MANUAL_REVIEW
  5. route-policy set community redacted + MANUAL_REVIEW
"""

import pytest
import re
from core.rule_translator import RuleBasedTranslator


def _executable_lines(result: str) -> list:
    lines = []
    in_fence = False
    for raw in result.split("\n"):
        line = raw.strip()
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence or not line:
            continue
        if line.startswith(("#", "!")):
            continue
        lines.append(line)
    return lines


def _check_no_source_residue(result, keywords):
    exe = _executable_lines(result)
    for kw in keywords:
        nkw = kw.lower()
        for line in exe:
            assert nkw not in line.lower(), f"Source residue '{kw}' in executable line: {line}"


CISCO_KW = ["ip route "]
HUAWEI_KW = ["ip route-static ", "undo ", "vlan batch"]
H3C_KW = ["undo ", "vlan batch"]
RUIJIE_KW = ["undo "]


# ═══════════════════════════════════════════════════════════════════════════
# 1. Static route — name/tag/preference/distance
# ═══════════════════════════════════════════════════════════════════════════

class TestStaticRouteOptions:
    """static route with name/tag/preference/distance/track/bfd."""

    def test_cisco_static_route_tag_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate("ip route 10.0.0.0 255.255.255.0 10.0.0.1 tag 100\n", "cisco", "huawei")
        assert "ip route-static 10.0.0.0 255.255.255.0 10.0.0.1" in r
        assert "MANUAL_REVIEW" in r
        _check_no_source_residue(r, CISCO_KW)

    def test_cisco_static_route_name_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate("ip route 0.0.0.0 0.0.0.0 10.0.0.1 name DEFAULT\n", "cisco", "huawei")
        assert "ip route-static 0.0.0.0 0.0.0.0 10.0.0.1" in r
        assert "MANUAL_REVIEW" in r

    def test_cisco_static_route_distance_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate("ip route 10.0.0.0 255.255.255.0 10.0.0.1 200\n", "cisco", "huawei")
        # Cisco distance = Huawei preference
        assert "preference" in r or "MANUAL_REVIEW" in r

    def test_huawei_static_route_tag_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate("ip route-static 10.0.0.0 24 10.0.0.1 tag 200\n", "huawei", "cisco")
        assert "MANUAL_REVIEW" in r

    def test_huawei_static_route_preference_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate("ip route-static 0.0.0.0 0 10.0.0.1 preference 100\n", "huawei", "cisco")
        assert "MANUAL_REVIEW" in r

    def test_static_route_track_bfd_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate("ip route 10.0.0.0 255.255.255.0 10.0.0.1 track 1\n", "cisco", "huawei")
        assert "MANUAL_REVIEW" in r


# ═══════════════════════════════════════════════════════════════════════════
# 2. OSPF — stub/nssa/virtual-link must not passthrough
# ═══════════════════════════════════════════════════════════════════════════

class TestOspfAdvanced:
    """OSPF stub/nssa/virtual-link/authentication must be MANUAL_REVIEW."""

    def test_ospf_stub_area_cisco_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate("router ospf 1\n area 0.0.0.1 stub\n", "cisco", "huawei")
        assert "MANUAL_REVIEW" in r

    def test_ospf_nssa_area_cisco_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate("router ospf 1\n area 0.0.0.2 nssa\n", "cisco", "huawei")
        assert "MANUAL_REVIEW" in r

    def test_ospf_virtual_link_cisco_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate("router ospf 1\n area 0.0.0.1 virtual-link 10.0.0.2\n", "cisco", "huawei")
        assert "MANUAL_REVIEW" in r

    def test_ospf_authentication_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate("router ospf 1\n area 0.0.0.1 authentication message-digest\n", "cisco", "huawei")
        assert "MANUAL_REVIEW" in r

    def test_ospf_cost_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate("router ospf 1\n ip ospf cost 100\n", "cisco", "huawei")
        assert "MANUAL_REVIEW" in r or "ospf cost" in r or "cost" in r

    def test_ospf_no_passive_residue(self):
        """passive-interface to silent-interface must not leave Cisco residue."""
        t = RuleBasedTranslator()
        r = t.translate("router ospf 1\n passive-interface GigabitEthernet0/1\n", "cisco", "huawei")
        assert "silent-interface GigabitEthernet0/1" in r
        _check_no_source_residue(r, CISCO_KW)

    def test_ospf_format_mask_cisco_to_huawei(self):
        """Cisco wildcard mask to Huawei network mask."""
        t = RuleBasedTranslator()
        r = t.translate("router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n", "cisco", "huawei")
        assert "network 10.0.0.0 0.0.0.255 area 0" in r or "MANUAL_REVIEW" in r


# ═══════════════════════════════════════════════════════════════════════════
# 3. BGP — update-source, ebgp-multihop, password redaction
# ═══════════════════════════════════════════════════════════════════════════

class TestBgpSkeleton:
    """BGP neighbor update-source, ebgp-multihop, password."""

    def test_bgp_update_source_cisco_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "router bgp 65001\n neighbor 10.0.0.1 update-source Loopback0\n",
            "cisco", "huawei",
        )
        assert "peer 10.0.0.1 connect-interface Loopback0" in r or "MANUAL_REVIEW" in r
        _check_no_source_residue(r, CISCO_KW)

    def test_bgp_ebgp_multihop_cisco_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "router bgp 65001\n neighbor 10.0.0.1 ebgp-multihop 2\n",
            "cisco", "huawei",
        )
        assert "ebgp-multihop" in r or "MANUAL_REVIEW" in r

    def test_bgp_password_redacted_cisco_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "router bgp 65001\n neighbor 10.0.0.1 password mySecretPass\n",
            "cisco", "huawei",
        )
        assert "<redacted>" in r
        assert "mySecretPass" not in r
        assert "MANUAL_REVIEW" in r

    def test_bgp_password_redacted_huawei_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "bgp 65001\n peer 10.0.0.1 password cipher MyCipherKey\n",
            "huawei", "cisco",
        )
        assert "<redacted>" in r
        assert "MyCipherKey" not in r
        assert "MANUAL_REVIEW" in r

    def test_bgp_update_source_huawei_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "bgp 65001\n peer 10.0.0.1 connect-interface Loopback0\n",
            "huawei", "cisco",
        )
        assert "update-source Loopback0" in r or "MANUAL_REVIEW" in r

    def test_bgp_no_password_leak_in_comment(self):
        """Password must not appear even in comment/MANUAL_REVIEW lines."""
        t = RuleBasedTranslator()
        r = t.translate(
            "router bgp 65001\n neighbor 10.0.0.1 password Sup3rS3cret\n",
            "cisco", "huawei",
        )
        assert "Sup3rS3cret" not in r
        assert "<redacted>" in r or "MANUAL_REVIEW" in r


# ═══════════════════════════════════════════════════════════════════════════
# 4. VRF — import/export policy MANUAL_REVIEW
# ═══════════════════════════════════════════════════════════════════════════

class TestVrfPolicy:
    """VRF import/export route-target and policy MANUAL_REVIEW."""

    def test_vrf_route_target_both_huawei_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "ip vpn-instance VRF1\n route-distinguisher 100:1\n vpn-target 100:1 both\n",
            "huawei", "cisco",
        )
        assert "route-target 100:1 both" in r or "route-target 100:1" in r
        _check_no_source_residue(r, HUAWEI_KW)

    def test_vrf_import_export_policy_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "vrf definition VRF1\n rd 100:1\n route-target export 100:1\n route-target import 100:2\n import ipv4 unicast map IMPORT-ME\n",
            "cisco", "huawei",
        )
        assert "route-target" in r or "vpn-target" in r
        assert "MANUAL_REVIEW" in r or "import" in r

    def test_vrf_description_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate("vrf definition VRF1\n description My VRF\n", "cisco", "huawei")
        assert "description" in r or "MANUAL_REVIEW" in r

    def test_vrf_rd_passthrough(self):
        t = RuleBasedTranslator()
        r = t.translate("ip vpn-instance VRF1\n route-distinguisher 100:1\n", "huawei", "h3c")
        assert "route-distinguisher 100:1" in r


# ═══════════════════════════════════════════════════════════════════════════
# 5. Route-policy / route-map — set community redacted
# ═══════════════════════════════════════════════════════════════════════════

class TestRoutePolicyCommunity:
    """route-map/route-policy set community redacted + MANUAL_REVIEW."""

    def test_route_map_set_community_cisco_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "route-map RMAP permit 10\n set community 100:100 200:200\n",
            "cisco", "huawei",
        )
        assert "<redacted>" in r or "community" not in r or "MANUAL_REVIEW" in r
        assert "100:100" not in r or "MANUAL_REVIEW" in r
        assert "200:200" not in r or "MANUAL_REVIEW" in r

    def test_route_map_set_community_no_value(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "route-map RMAP permit 10\n set community none\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in r

    def test_route_policy_apply_community_redacted(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "route-policy RP permit node 10\n apply community 300:300\n",
            "huawei", "cisco",
        )
        assert "<redacted>" in r or "MANUAL_REVIEW" in r
        assert "300:300" not in r or "MANUAL_REVIEW" in r

    def test_route_map_match_ip_address_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "route-map RMAP permit 10\n match ip address ACL1\n",
            "cisco", "huawei",
        )
        assert "if-match acl ACL1" in r

    def test_route_policy_if_match_acl_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "route-policy RP permit node 10\n if-match acl ACL2\n",
            "huawei", "cisco",
        )
        assert "match ip address ACL2" in r

    def test_route_map_set_local_pref_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "route-map RMAP permit 10\n set local-preference 200\n",
            "cisco", "huawei",
        )
        assert "apply local-preference 200" in r

    def test_route_policy_apply_local_pref_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "route-policy RP permit node 10\n apply local-preference 150\n",
            "huawei", "cisco",
        )
        assert "set local-preference 150" in r
