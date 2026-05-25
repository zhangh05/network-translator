# -*- coding: utf-8 -*-
"""Batch K-C: FIREWALL fallback translation hardening tests.

Priority items (P0):
  1. DPtech address-range -> Hillstone MANUAL_REVIEW
  2. Hillstone address range (two IPs) -> Huawei USG MANUAL_REVIEW [BUG: auto-translates as subnet]
  3. Topsec address-group -> Hillstone MANUAL_REVIEW
  4. DPtech address-group -> Hillstone MANUAL_REVIEW
  5. Hillstone service multi-port (80,443) -> Huawei USG MANUAL_REVIEW
  6. Topsec service icmp -> Hillstone auto-translate
  7. Hillstone zone + add interface -> Huawei USG (zone auto, bind MANUAL_REVIEW)
  8. Hillstone nat -> Huawei USG MANUAL_REVIEW
  9. DPtech nat -> Hillstone MANUAL_REVIEW
 10. Hillstone address-set -> Huawei USG MANUAL_REVIEW
 11. Hillstone service-set -> Huawei USG MANUAL_REVIEW
 12. DPtech service icmp -> Hillstone MANUAL_REVIEW
 13. DPtech service tcp -> Huawei USG MANUAL_REVIEW
"""

import pytest
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


# ═══════════════════════════════════════════════════════════════════════════
# 1. DPtech address-range -> Hillstone
# ═══════════════════════════════════════════════════════════════════════════

class TestDptechAddressRange:
    def test_dptech_address_range_to_hillstone_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "object address-range RANGE1 10.0.0.1 10.0.0.254\n",
            "dptech", "hillstone",
        )
        assert "MANUAL_REVIEW" in r
        exe = _executable_lines(r)
        assert len(exe) == 0, f"No executable lines should survive: {exe}"


# ═══════════════════════════════════════════════════════════════════════════
# 2. Hillstone address range (two IPs) -> Huawei USG [BUG]
# ═══════════════════════════════════════════════════════════════════════════

class TestHillstoneAddressRange:
    def test_hillstone_address_two_ip_range_to_huawei_usg_manual_review(self):
        """address RANGE 10.0.0.1 10.0.0.254 is a RANGE, not a subnet.
        Current code incorrectly treats 10.0.0.254 as a netmask -> mask 9.
        Must produce MANUAL_REVIEW instead."""
        t = RuleBasedTranslator()
        r = t.translate(
            "address RANGE 10.0.0.1 10.0.0.254\n",
            "hillstone", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in r
        exe = _executable_lines(r)
        assert len(exe) == 0, f"No executable lines: {exe}"

    def test_hillstone_address_subnet_still_auto(self):
        """Valid subnet (global unicast IP) still auto-translates."""
        t = RuleBasedTranslator()
        r = t.translate(
            "address TRUSTED 10.0.0.0 255.255.255.0\n",
            "hillstone", "huawei_usg",
        )
        exe = _executable_lines(r)
        assert any("address 0 10.0.0.0 mask 24" in l or "10.0.0.0" in l for l in exe)


# ═══════════════════════════════════════════════════════════════════════════
# 3. Topsec address-group -> Hillstone
# ═══════════════════════════════════════════════════════════════════════════

class TestTopsecAddressGroup:
    def test_topsec_address_group_to_hillstone_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate("address-group GROUP1\n", "topsec", "hillstone")
        assert "MANUAL_REVIEW" in r


# ═══════════════════════════════════════════════════════════════════════════
# 4. DPtech address-group -> Hillstone
# ═══════════════════════════════════════════════════════════════════════════

class TestDptechAddressGroup:
    def test_dptech_address_group_to_hillstone_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate("address-group GROUP1\n", "dptech", "hillstone")
        assert "MANUAL_REVIEW" in r


# ═══════════════════════════════════════════════════════════════════════════
# 5. Hillstone service multi-port -> Huawei USG
# ═══════════════════════════════════════════════════════════════════════════

class TestHillstoneServiceMultiPort:
    def test_hillstone_service_multi_port_to_huawei_usg_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "service WEB tcp 80,443\n",
            "hillstone", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in r


# ═══════════════════════════════════════════════════════════════════════════
# 6. Topsec service icmp -> Hillstone auto
# ═══════════════════════════════════════════════════════════════════════════

class TestTopsecServiceIcmp:
    def test_topsec_service_icmp_to_hillstone_auto(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "service PING protocol icmp\n",
            "topsec", "hillstone",
        )
        exe = _executable_lines(r)
        assert any("service PING icmp" in l for l in exe)


# ═══════════════════════════════════════════════════════════════════════════
# 7. Hillstone zone interface binding -> Huawei USG
# ═══════════════════════════════════════════════════════════════════════════

class TestHillstoneZoneBind:
    def test_hillstone_zone_interface_binding_to_huawei_usg_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "zone trust\n add interface GigabitEthernet0/0/1\n",
            "hillstone", "huawei_usg",
        )
        assert "security-zone name trust" in r
        assert "MANUAL_REVIEW" in r
        assert "add interface" in r


# ═══════════════════════════════════════════════════════════════════════════
# 8. Hillstone nat -> Huawei USG
# ═══════════════════════════════════════════════════════════════════════════

class TestHillstoneNat:
    def test_hillstone_nat_to_huawei_usg_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "nat source 10.0.0.0 255.255.255.0\n",
            "hillstone", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in r


# ═══════════════════════════════════════════════════════════════════════════
# 9. DPtech nat -> Hillstone
# ═══════════════════════════════════════════════════════════════════════════

class TestDptechNat:
    def test_dptech_nat_to_hillstone_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate("nat address-group GROUP1\n", "dptech", "hillstone")
        assert "MANUAL_REVIEW" in r


# ═══════════════════════════════════════════════════════════════════════════
# 10. Hillstone address-set -> Huawei USG
# ═══════════════════════════════════════════════════════════════════════════

class TestHillstoneAddressSet:
    def test_hillstone_address_set_to_huawei_usg_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "address-set INTERNAL 10.0.0.0 255.255.255.0\n",
            "hillstone", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in r


# ═══════════════════════════════════════════════════════════════════════════
# 11. Hillstone service-set -> Huawei USG
# ═══════════════════════════════════════════════════════════════════════════

class TestHillstoneServiceSet:
    def test_hillstone_service_set_to_huawei_usg_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "service-set HTTP-GROUP tcp dst-port 80\n",
            "hillstone", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in r


# ═══════════════════════════════════════════════════════════════════════════
# 12. DPtech service icmp -> Hillstone
# ═══════════════════════════════════════════════════════════════════════════

class TestDptechServiceIcmp:
    def test_dptech_service_icmp_to_hillstone_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "object service PING protocol icmp\n",
            "dptech", "hillstone",
        )
        assert "MANUAL_REVIEW" in r


# ═══════════════════════════════════════════════════════════════════════════
# 13. DPtech service tcp -> Huawei USG
# ═══════════════════════════════════════════════════════════════════════════

class TestDptechServiceTcp:
    def test_dptech_service_tcp_to_huawei_usg_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "object service HTTP protocol tcp destination-port 80\n",
            "dptech", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in r
