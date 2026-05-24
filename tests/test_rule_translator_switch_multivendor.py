# -*- coding: utf-8 -*-
"""Multi-vendor switch translation tests for deterministic fallback."""

import pytest
from core.rule_translator import RuleBasedTranslator

CISCO_KW = ["channel-group", "ip route "]
HUAWEI_KW = ["undo "]
H3C_KW = ["undo ", "bridge-aggregation"]
RUIJIE_KW = ["aggregateport", "port-group"]


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


# ── 12 vendor directions: each has hostname + vlan + intf + trunk/access + SVI/LAG/STP ──

def test_cisco_to_huawei_switch():
    t = RuleBasedTranslator()
    r = t.translate(
        "hostname SW\nvlan 10\nvlan 20,30\n"
        "interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n"
        "interface Vlan10\n ip address 10.0.0.1 255.255.255.0\n"
        "spanning-tree portfast\n",
        "cisco", "huawei",
    )
    assert "sysname SW" in r
    assert "vlan 10" in r or "vlan batch 10" in r
    assert "interface XGigabitEthernet" not in r
    assert "interface GigabitEthernet0/1" in r
    assert "port link-type trunk" in r
    assert "port trunk allow-pass vlan" in r
    assert "interface Vlanif10" in r
    assert "ip address 10.0.0.1 255.255.255.0" in r
    assert "stp edged-port enable" in r
    _check_no_source_residue(r, CISCO_KW)


def test_cisco_to_h3c_switch():
    t = RuleBasedTranslator()
    r = t.translate(
        "hostname SW\nvlan 10\nvlan 20,30\n"
        "interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n"
        "interface Vlan10\n ip address 10.0.0.1 255.255.255.0\n"
        "spanning-tree portfast\n channel-group 1 mode active\n",
        "cisco", "h3c",
    )
    assert "sysname SW" in r
    assert "vlan 10" in r
    assert "interface GigabitEthernet0/1" in r
    assert "port link-type trunk" in r
    assert "port trunk permit vlan" in r
    assert "interface Vlan-interface10" in r
    assert "stp edged-port" in r
    assert "port link-aggregation group 1" in r
    _check_no_source_residue(r, CISCO_KW)


def test_cisco_to_ruijie_switch():
    t = RuleBasedTranslator()
    r = t.translate(
        "hostname SW\nvlan 10\nvlan 20,30\n"
        "interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n"
        "interface Vlan10\n ip address 10.0.0.1 255.255.255.0\n"
        "spanning-tree portfast\n channel-group 1 mode active\n",
        "cisco", "ruijie",
    )
    assert "hostname SW" in r
    assert "vlan 10" in r
    assert "interface GigabitEthernet0/1" in r
    assert "switchport mode trunk" in r
    assert "switchport trunk allowed vlan" in r
    assert "interface Vlan10" in r
    assert "spanning-tree portfast" in r
    assert "port-group 1 mode active" in r
    _check_no_source_residue(r, CISCO_KW)


def test_huawei_to_cisco_switch():
    t = RuleBasedTranslator()
    r = t.translate(
        "sysname SW\nvlan batch 10 20 30\n"
        "interface GigabitEthernet1/0/1\n port link-type trunk\n port trunk allow-pass vlan 10 20\n"
        "interface Vlanif10\n ip address 10.0.0.1 255.255.255.0\n"
        "stp edged-port enable\n eth-trunk 1\n",
        "huawei", "cisco",
    )
    assert "hostname SW" in r
    assert "vlan 10,20,30" in r or "vlan 10" in r
    assert "interface GigabitEthernet1/0/1" in r
    assert "switchport mode trunk" in r
    assert "switchport trunk allowed vlan" in r
    assert "interface Vlan10" in r
    assert "spanning-tree portfast" in r
    assert "channel-group 1 mode active" in r
    _check_no_source_residue(r, HUAWEI_KW)


def test_huawei_to_h3c_switch():
    t = RuleBasedTranslator()
    r = t.translate(
        "sysname SW\nvlan batch 10 20 30\n"
        "interface GigabitEthernet1/0/1\n port link-type trunk\n port trunk allow-pass vlan 10 20\n"
        "interface Vlanif10\n ip address 10.0.0.1 255.255.255.0\n"
        "stp edged-port enable\n eth-trunk 1\n",
        "huawei", "h3c",
    )
    assert "sysname SW" in r
    assert "vlan 10 to 20" in r or "vlan batch" in r
    assert "interface GigabitEthernet1/0/1" in r
    assert "port link-type trunk" in r
    assert "port trunk permit vlan" in r or "port trunk allow-pass vlan" in r
    assert "interface Vlan-interface10" in r
    assert "stp edged-port" in r
    assert "port link-aggregation group 1" in r or "bridge-aggregation" in r
    _check_no_source_residue(r, HUAWEI_KW)


def test_huawei_to_ruijie_switch():
    t = RuleBasedTranslator()
    r = t.translate(
        "sysname SW\nvlan batch 10 20 30\n"
        "interface GigabitEthernet1/0/1\n port link-type trunk\n port trunk allow-pass vlan 10 20\n"
        "interface Vlanif10\n ip address 10.0.0.1 255.255.255.0\n"
        "stp edged-port enable\n eth-trunk 1\n",
        "huawei", "ruijie",
    )
    assert "hostname SW" in r
    assert "interface GigabitEthernet1/0/1" in r
    assert "switchport mode trunk" in r
    assert "switchport trunk allowed vlan" in r
    assert "interface Vlan10" in r
    assert "spanning-tree portfast" in r
    assert "port-group 1 mode active" in r
    _check_no_source_residue(r, HUAWEI_KW)


def test_h3c_to_cisco_switch():
    t = RuleBasedTranslator()
    r = t.translate(
        "sysname SW\nvlan 10\nvlan 10 to 20\n"
        "interface GigabitEthernet1/0/1\n port link-type trunk\n port trunk permit vlan 10 20\n"
        "interface Vlan-interface10\n ip address 10.0.0.1 255.255.255.0\n"
        "stp edged-port\n bridge-aggregation 1\n",
        "h3c", "cisco",
    )
    assert "hostname SW" in r
    assert "vlan 10-20" in r or "vlan 10" in r
    assert "interface GigabitEthernet1/0/1" in r
    assert "switchport mode trunk" in r
    assert "switchport trunk allowed vlan" in r
    assert "interface Vlan10" in r
    assert "spanning-tree portfast" in r
    assert "channel-group 1 mode active" in r
    _check_no_source_residue(r, H3C_KW)


def test_h3c_to_huawei_switch():
    t = RuleBasedTranslator()
    r = t.translate(
        "sysname SW\nvlan 10\nvlan 10 to 20\n"
        "interface GigabitEthernet1/0/1\n port link-type trunk\n port trunk permit vlan 10 20\n"
        "interface Vlan-interface10\n ip address 10.0.0.1 255.255.255.0\n"
        "stp edged-port\n bridge-aggregation 1\n",
        "h3c", "huawei",
    )
    assert "sysname SW" in r
    assert "interface GigabitEthernet1/0/1" in r
    assert "port link-type trunk" in r
    assert "interface Vlanif10" in r
    assert "stp edged-port enable" in r
    assert "eth-trunk 1" in r
    _check_no_source_residue(r, H3C_KW)


def test_h3c_to_ruijie_switch():
    t = RuleBasedTranslator()
    r = t.translate(
        "sysname SW\nvlan 10\nvlan 10 to 20\n"
        "interface GigabitEthernet1/0/1\n port link-type trunk\n port trunk permit vlan 10 20\n"
        "interface Vlan-interface10\n ip address 10.0.0.1 255.255.255.0\n"
        "stp edged-port\n bridge-aggregation 1\n",
        "h3c", "ruijie",
    )
    assert "hostname SW" in r
    assert "interface GigabitEthernet1/0/1" in r
    assert "switchport mode trunk" in r
    assert "interface Vlan10" in r
    assert "spanning-tree portfast" in r
    assert "port-group 1 mode active" in r
    _check_no_source_residue(r, H3C_KW)


def test_ruijie_to_cisco_switch():
    t = RuleBasedTranslator()
    r = t.translate(
        "hostname SW\nvlan 10\nvlan 10-20\n"
        "interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n"
        "interface Vlan10\n ip address 10.0.0.1 255.255.255.0\n"
        "spanning-tree portfast\n port-group 1 mode active\n",
        "ruijie", "cisco",
    )
    assert "hostname SW" in r
    assert "interface GigabitEthernet0/1" in r
    assert "switchport mode trunk" in r
    assert "switchport trunk allowed vlan" in r
    assert "interface Vlan10" in r
    assert "spanning-tree portfast" in r
    assert "channel-group 1 mode active" in r
    _check_no_source_residue(r, RUIJIE_KW)


def test_ruijie_to_huawei_switch():
    t = RuleBasedTranslator()
    r = t.translate(
        "hostname SW\nvlan 10\nvlan 10-20\n"
        "interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n"
        "interface Vlan10\n ip address 10.0.0.1 255.255.255.0\n"
        "spanning-tree portfast\n port-group 1 mode active\n",
        "ruijie", "huawei",
    )
    assert "sysname SW" in r
    assert "interface GigabitEthernet0/1" in r
    assert "port link-type trunk" in r
    assert "interface Vlanif10" in r
    assert "stp edged-port enable" in r
    assert "eth-trunk 1" in r
    _check_no_source_residue(r, RUIJIE_KW)


def test_ruijie_to_h3c_switch():
    t = RuleBasedTranslator()
    r = t.translate(
        "hostname SW\nvlan 10\nvlan 10-20\n"
        "interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n"
        "interface Vlan10\n ip address 10.0.0.1 255.255.255.0\n"
        "spanning-tree portfast\n port-group 1 mode active\n",
        "ruijie", "h3c",
    )
    assert "sysname SW" in r
    assert "interface GigabitEthernet0/1" in r
    assert "port link-type trunk" in r
    assert "interface Vlan-interface10" in r
    assert "stp edged-port" in r
    assert "port link-aggregation group 1" in r or "bridge-aggregation" in r
    _check_no_source_residue(r, RUIJIE_KW)


# ── MANUAL_REVIEW for unknown/bpdu/loop/guard ──

def test_unknown_switch_command_manual_review():
    for frm, to in [("cisco","huawei"), ("cisco","h3c"), ("cisco","ruijie"),
                    ("huawei","cisco"), ("huawei","h3c"), ("huawei","ruijie"),
                    ("h3c","cisco"), ("h3c","huawei"), ("h3c","ruijie"),
                    ("ruijie","cisco"), ("ruijie","huawei"), ("ruijie","h3c")]:
        t = RuleBasedTranslator()
        r = t.translate("spanning-tree bpduguard enable\n", frm, to)
        assert "MANUAL_REVIEW" in r, f"{frm}->{to} should MANUAL_REVIEW bpduguard"
        exe = _executable_lines(r)
        assert not any("spanning-tree" in x.lower() for x in exe), f"{frm}->{to}: bpduguard leaked: {exe}"


def test_route_map_prefix_list_manual_review():
    """route-map/route-policy/prefix-list must never be executable in output."""
    for frm, to in [("cisco","huawei"), ("huawei","cisco"), ("h3c","ruijie"), ("ruijie","h3c")]:
        t = RuleBasedTranslator()
        r = t.translate("route-map RM permit 10\n match ip address prefix-list PL\n", frm, to)
        assert "MANUAL_REVIEW" in r, f"{frm}->{to} must MANUAL_REVIEW route-map"
        exe = _executable_lines(r)
        assert not any("route-map" in x.lower() for x in exe), f"{frm}->{to}: route-map leaked: {exe}"


# ── Negative tests: residue checker must reject source residue ──

def test_switch_residue_checker_catches_source_undo():
    fake_output = "```huawei\nundo shutdown\nport link-type trunk\n```"
    with pytest.raises(AssertionError):
        _check_no_source_residue(fake_output, HUAWEI_KW)


def test_switch_residue_checker_catches_source_bridge_aggregation():
    fake_output = "```h3c\nbridge-aggregation 1\n```"
    with pytest.raises(AssertionError):
        _check_no_source_residue(fake_output, H3C_KW)


# ── Batch C: interface range / native vlan / shutdown cycle ──

def test_interface_range_huawei_to_cisco():
    t = RuleBasedTranslator()
    r = t.translate("interface range GigabitEthernet0/0/1-4\n switchport mode access\n", "huawei", "cisco")
    assert "interface range GigabitEthernet0/0/1-4" in r
    assert "switchport mode access" in r
    _check_no_source_residue(r, HUAWEI_KW)


def test_native_vlan_huawei_to_cisco():
    t = RuleBasedTranslator()
    r = t.translate("port trunk pvid vlan 10\n", "huawei", "cisco")
    assert "MANUAL_REVIEW" in r, "port trunk pvid vlan must produce MANUAL_REVIEW"


def test_shutdown_cycle_cisco_to_huawei():
    t = RuleBasedTranslator()
    r = t.translate("interface GigabitEthernet0/1\n shutdown\n", "cisco", "huawei")
    assert "shutdown" in r
    _check_no_source_residue(r, CISCO_KW)


TRUNK_ALLOWED_INPUT = "interface GigabitEthernet1/0/1\n switchport mode trunk\n switchport trunk allowed vlan 20,30\n"


def test_cisco_trunk_allowed_to_huawei_uses_allow_pass_not_permit():
    t = RuleBasedTranslator()
    r = t.translate(TRUNK_ALLOWED_INPUT, "cisco", "huawei")
    exec_lines = _executable_lines(r)
    assert any("port trunk allow-pass vlan 20 30" in line for line in exec_lines), (
        f"Expected 'port trunk allow-pass vlan 20 30' in executable lines: {exec_lines}"
    )
    assert not any("port trunk permit vlan" in line for line in exec_lines), (
        f"Should NOT contain 'port trunk permit vlan' in executable lines: {exec_lines}"
    )


def test_cisco_trunk_allowed_to_h3c_uses_permit_not_allow_pass():
    t = RuleBasedTranslator()
    r = t.translate(TRUNK_ALLOWED_INPUT, "cisco", "h3c")
    exec_lines = _executable_lines(r)
    assert any("port trunk permit vlan 20 30" in line for line in exec_lines), (
        f"Expected 'port trunk permit vlan 20 30' in executable lines: {exec_lines}"
    )
    assert not any("port trunk allow-pass vlan" in line for line in exec_lines), (
        f"Should NOT contain 'port trunk allow-pass vlan' in executable lines: {exec_lines}"
    )


def test_huawei_undo_portswitch_to_cisco_no_switchport():
    t = RuleBasedTranslator()
    r = t.translate(
        "interface XGigabitEthernet0/0/1\n undo portswitch\n ip address 10.0.0.1 255.255.255.0\n",
        "huawei",
        "cisco",
    )
    exec_lines = _executable_lines(r)
    assert any(line == "no switchport" for line in exec_lines), exec_lines
    assert not any("undo portswitch" in line for line in exec_lines), exec_lines
