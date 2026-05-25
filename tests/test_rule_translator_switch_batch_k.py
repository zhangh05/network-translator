# -*- coding: utf-8 -*-
"""Batch K-A: SWITCH fallback translation hardening tests.

Tests for:
  1. trunk allowed vlan add/remove/all/none
  2. access vlan / native vlan / pvid
  3. interface range
  4. shutdown / undo shutdown consistency
  5. description / vlan name
  6. stp edge / bpdu / root guard
"""

import pytest
import re
from core.rule_translator import RuleBasedTranslator


# ── Helpers (copied from existing test files) ──────────────────────────────


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


CISCO_KW = ["channel-group", "ip route "]
HUAWEI_KW = ["undo ", "vlan batch", "eth-trunk"]
H3C_KW = ["undo ", "vlan batch"]
RUIJIE_KW = ["undo ", "vlan batch"]


# ═══════════════════════════════════════════════════════════════════════════
# 1. trunk allowed vlan — add/remove/all/none
# ═══════════════════════════════════════════════════════════════════════════

class TestTrunkAllowedVlanAddRemove:
    """switchport trunk allowed vlan add/remove/all/none + undo equivalents."""

    # ── Cisco add → Huawei ─────────────────────────────────────────────

    def test_cisco_trunk_add_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport trunk allowed vlan add 10,20\n",
            "cisco", "huawei",
        )
        assert "port trunk allow-pass vlan" in r
        assert "10" in r and "20" in r
        assert "MANUAL_REVIEW" in r
        _check_no_source_residue(r, CISCO_KW)

    def test_cisco_trunk_add_single_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport trunk allowed vlan add 30\n",
            "cisco", "huawei",
        )
        assert "port trunk allow-pass vlan 30" in r
        assert "MANUAL_REVIEW" in r

    def test_cisco_trunk_add_to_h3c(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport trunk allowed vlan add 15\n",
            "cisco", "h3c",
        )
        assert "port trunk permit vlan 15" in r or "port trunk allow-pass vlan 15" in r
        assert "MANUAL_REVIEW" in r

    def test_cisco_trunk_add_to_ruijie(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport trunk allowed vlan add 25\n",
            "cisco", "ruijie",
        )
        assert "switchport trunk allowed vlan" in r
        assert "25" in r
        assert "MANUAL_REVIEW" in r

    # ── Cisco remove → Huawei undo ─────────────────────────────────────

    def test_cisco_trunk_remove_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport trunk allowed vlan remove 10\n",
            "cisco", "huawei",
        )
        assert "undo port trunk allow-pass vlan 10" in r or "undo port trunk permit vlan 10" in r
        _check_no_source_residue(r, CISCO_KW)

    def test_cisco_trunk_remove_multi_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport trunk allowed vlan remove 10,20\n",
            "cisco", "huawei",
        )
        assert "undo" in r
        assert "10" in r and "20" in r

    def test_cisco_trunk_remove_to_h3c(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport trunk allowed vlan remove 15\n",
            "cisco", "h3c",
        )
        assert "undo" in r
        assert "permit vlan" in r or "allow-pass vlan" in r
        assert "15" in r

    # ── Cisco all/none → MANUAL_REVIEW ──────────────────────────────────

    def test_cisco_trunk_all_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport trunk allowed vlan all\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in r
        _check_no_source_residue(r, CISCO_KW)

    def test_cisco_trunk_none_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport trunk allowed vlan none\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in r

    # ── Huawei undo allow-pass → Cisco ──────────────────────────────────

    def test_huawei_undo_allow_pass_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n undo port trunk allow-pass vlan 10\n",
            "huawei", "cisco",
        )
        assert "switchport trunk allowed vlan remove" in r or "MANUAL_REVIEW" in r
        _check_no_source_residue(r, HUAWEI_KW)

    # ── Huawei undo allow-pass → H3C ────────────────────────────────────

    def test_huawei_undo_allow_pass_to_h3c(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n undo port trunk allow-pass vlan 10,20\n",
            "huawei", "h3c",
        )
        assert "undo port trunk permit vlan" in r or "undo port trunk allow-pass vlan" in r
        assert "10" in r and "20" in r

    # ── H3C undo permit → Cisco ─────────────────────────────────────────

    def test_h3c_undo_permit_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n undo port trunk permit vlan 30\n",
            "h3c", "cisco",
        )
        assert "switchport trunk allowed vlan remove" in r or "MANUAL_REVIEW" in r

    def test_h3c_undo_permit_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n undo port trunk permit vlan 15,25\n",
            "h3c", "huawei",
        )
        assert "undo port trunk allow-pass vlan" in r
        assert "15" in r and "25" in r

    # ── Ruijie trunk allowed vlan add → others ──────────────────────────

    def test_ruijie_trunk_add_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport trunk allowed vlan add 40\n",
            "ruijie", "huawei",
        )
        assert "port trunk allow-pass vlan" in r
        assert "MANUAL_REVIEW" in r


# ═══════════════════════════════════════════════════════════════════════════
# 2. access vlan / native vlan / pvid
# ═══════════════════════════════════════════════════════════════════════════

class TestAccessNativePvid:
    """access vlan / native vlan / pvid inter-vendor mapping."""

    # ── Cisco native vlan → Huawei pvid ──────────────────────────────────

    def test_cisco_native_vlan_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport trunk native vlan 10\n",
            "cisco", "huawei",
        )
        assert "port trunk pvid vlan 10" in r
        _check_no_source_residue(r, CISCO_KW)

    def test_cisco_native_vlan_to_h3c(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport trunk native vlan 99\n",
            "cisco", "h3c",
        )
        assert "port trunk pvid vlan 99" in r

    def test_cisco_native_vlan_to_ruijie(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport trunk native vlan 5\n",
            "cisco", "ruijie",
        )
        assert "switchport trunk native vlan 5" in r or "native vlan" in r

    # ── Huawei pvid → Cisco native vlan ─────────────────────────────────

    def test_huawei_pvid_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n port trunk pvid vlan 10\n",
            "huawei", "cisco",
        )
        assert "switchport trunk native vlan 10" in r
        _check_no_source_residue(r, HUAWEI_KW)

    def test_h3c_pvid_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n port trunk pvid vlan 99\n",
            "h3c", "cisco",
        )
        assert "switchport trunk native vlan 99" in r

    # ── Huawei pvid → H3C / Ruijie ──────────────────────────────────────

    def test_huawei_pvid_to_h3c(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n port trunk pvid vlan 20\n",
            "huawei", "h3c",
        )
        assert "pvid vlan 20" in r or "port trunk pvid vlan 20" in r

    def test_huawei_pvid_to_ruijie(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n port trunk pvid vlan 30\n",
            "huawei", "ruijie",
        )
        assert "native vlan" in r or "pvid" in r

    # ── Non-trunk context → MANUAL_REVIEW ────────────────────────────────

    def test_access_vlan_not_trunk_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n switchport access vlan 10\n",
            "cisco", "huawei",
        )
        # access vlan should not be confused with native/pvid
        assert "port default vlan 10" in r
        assert "pvid" not in r

    def test_native_vlan_no_mode_set_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n native vlan 10\n",
            "unknown", "cisco",
        )
        assert "MANUAL_REVIEW" in r


# ═══════════════════════════════════════════════════════════════════════════
# 3. interface range
# ═══════════════════════════════════════════════════════════════════════════

class TestInterfaceRange:
    """interface range must not be silently expanded or dropped."""

    def test_cisco_interface_range_to_huawei_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface range GigabitEthernet0/1 - 4\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in r
        assert "interface range" in r or "range" in r
        _check_no_source_residue(r, CISCO_KW)

    def test_cisco_interface_range_comma_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface range GigabitEthernet0/1,GigabitEthernet0/2\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in r

    def test_cisco_interface_range_to_h3c_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface range GigabitEthernet0/1 - 4\n",
            "cisco", "h3c",
        )
        assert "MANUAL_REVIEW" in r

    def test_cisco_interface_range_to_ruijie(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface range GigabitEthernet0/1 - 4\n",
            "cisco", "ruijie",
        )
        assert "MANUAL_REVIEW" in r or "interface range" in r

    def test_huawei_port_group_to_cisco_manual_review(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "port-group 1\n",
            "huawei", "cisco",
        )
        assert "MANUAL_REVIEW" in r or "channel-group" in r

    def test_no_silent_expand(self):
        """Verify ranges are not silently expanded into individual interfaces."""
        t = RuleBasedTranslator()
        r = t.translate(
            "interface range GigabitEthernet0/1 - 4\n",
            "cisco", "huawei",
        )
        exe = "\n".join(_executable_lines(r))
        # Should NOT have individual interface lines
        assert "interface GigabitEthernet0/1" not in exe
        assert "interface GigabitEthernet0/2" not in exe
        assert "interface GigabitEthernet0/3" not in exe
        assert "interface GigabitEthernet0/4" not in exe


# ═══════════════════════════════════════════════════════════════════════════
# 4. shutdown / undo shutdown consistency
# ═══════════════════════════════════════════════════════════════════════════

class TestShutdownConsistency:
    """shutdown / no shutdown / undo shutdown cross-vendor correctness."""

    def test_cisco_shutdown_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate("interface GigabitEthernet0/1\n shutdown\n", "cisco", "huawei")
        assert "shutdown" in _executable_lines(r)[-1]
        assert "undo" not in _executable_lines(r)[-1]

    def test_cisco_no_shutdown_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate("interface GigabitEthernet0/1\n no shutdown\n", "cisco", "huawei")
        assert "undo shutdown" in r

    def test_huawei_shutdown_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate("interface GigabitEthernet0/1\n shutdown\n", "huawei", "cisco")
        exe = _executable_lines(r)
        assert "shutdown" in exe[-1]

    def test_huawei_undo_shutdown_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate("interface GigabitEthernet0/1\n undo shutdown\n", "huawei", "cisco")
        assert "no shutdown" in r

    def test_shutdown_same_vendor_passthrough(self):
        t = RuleBasedTranslator()
        for v in ("cisco", "huawei", "h3c", "ruijie"):
            r = t.translate("interface GigabitEthernet0/1\n shutdown\n", v, v)
            exe = _executable_lines(r)
            assert "shutdown" in exe[-1]


# ═══════════════════════════════════════════════════════════════════════════
# 5. description / vlan name
# ═══════════════════════════════════════════════════════════════════════════

class TestDescription:
    """interface description and vlan name preservation."""

    def test_description_passthrough_cisco_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n description Uplink to Core\n",
            "cisco", "huawei",
        )
        assert "description Uplink to Core" in r

    def test_description_passthrough_huawei_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n description Link-to-Core\n",
            "huawei", "cisco",
        )
        assert "description Link-to-Core" in r

    def test_vlan_name_cisco_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate("vlan 10\n name Users\n", "cisco", "huawei")
        assert "description Users" in r or "name Users" in r
        _check_no_source_residue(r, CISCO_KW)

    def test_vlan_name_cisco_to_h3c(self):
        t = RuleBasedTranslator()
        r = t.translate("vlan 10\n name Users\n", "cisco", "h3c")
        assert "description Users" in r or "name Users" in r

    def test_vlan_description_huawei_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate("vlan 10\n description Servers\n", "huawei", "cisco")
        assert "name Servers" in r or "description Servers" in r

    def test_vlan_description_passthrough_huawei_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate("vlan 10\n description Servers\n", "huawei", "huawei")
        assert "description Servers" in r


# ═══════════════════════════════════════════════════════════════════════════
# 6. STP edge / bpdu / root guard
# ═══════════════════════════════════════════════════════════════════════════

class TestStpGuards:
    """spanning-tree bpduguard / root guard / loopguard."""

    # ── Cisco bpduguard → Huawei/H3C/Ruijie ─────────────────────────────

    def test_cisco_bpduguard_enable_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n spanning-tree bpduguard enable\n",
            "cisco", "huawei",
        )
        assert "bpdu-protection" in r or "bpduguard" in r
        _check_no_source_residue(r, CISCO_KW)

    def test_cisco_bpduguard_enable_to_h3c(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n spanning-tree bpduguard enable\n",
            "cisco", "h3c",
        )
        assert "bpdu-protection" in r or "bpduguard" in r or "bpdu" in r

    def test_cisco_bpduguard_enable_to_ruijie(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n spanning-tree bpduguard enable\n",
            "cisco", "ruijie",
        )
        assert "bpduguard" in r

    # ── Cisco root guard → others ───────────────────────────────────────

    def test_cisco_root_guard_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n spanning-tree guard root\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in r or "root-protection" in r

    def test_cisco_root_guard_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n spanning-tree guard root\n",
            "cisco", "cisco",
        )
        assert "spanning-tree guard root" in r

    # ── Cisco loopguard → others ────────────────────────────────────────

    def test_cisco_loopguard_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n spanning-tree guard loop\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in r

    # ── Huawei bpdu-protection → Cisco ──────────────────────────────────

    def test_huawei_bpdu_protection_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n stp bpdu-protection\n",
            "huawei", "cisco",
        )
        assert "spanning-tree bpduguard" in r or "bpduguard" in r

    # ── Huawei root-protection → Cisco ──────────────────────────────────

    def test_huawei_root_protection_to_cisco(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n stp root-protection\n",
            "huawei", "cisco",
        )
        assert "spanning-tree guard root" in r or "spanning-tree rootguard" in r or "MANUAL_REVIEW" in r

    # ── STP portfast edge port ─────────────────────────────────────────

    def test_stp_portfast_edge_to_huawei(self):
        t = RuleBasedTranslator()
        r = t.translate(
            "interface GigabitEthernet0/1\n spanning-tree portfast\n",
            "cisco", "huawei",
        )
        assert "stp edged-port enable" in r or "stp edged-port" in r
