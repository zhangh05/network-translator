# -*- coding: utf-8 -*-
"""Multi-vendor router translation tests for deterministic fallback."""

import pytest
from core.rule_translator import RuleBasedTranslator

CISCO_KW = ["switchport", "channel-group", "router ospf", "router bgp"]
HUAWEI_KW = ["undo ", "vlan batch", "eth-trunk"]
H3C_KW = ["undo ", "bridge-aggregation"]
RUIJIE_KW = ["port-group", "aggregateport"]


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


# ── Static Route ──

def test_static_route_cisco_to_huawei():
    t = RuleBasedTranslator()
    r = t.translate("ip route 0.0.0.0 0.0.0.0 10.0.0.1\n", "cisco", "huawei")
    assert "ip route-static 0.0.0.0 0.0.0.0 10.0.0.1" in r
    _check_no_source_residue(r, CISCO_KW)


def test_static_route_huawei_to_cisco():
    t = RuleBasedTranslator()
    r = t.translate("ip route-static 0.0.0.0 0.0.0.0 10.0.0.1\n", "huawei", "cisco")
    assert "ip route 0.0.0.0 0.0.0.0 10.0.0.1" in r
    _check_no_source_residue(r, HUAWEI_KW)


def test_static_route_huawei_options_manual_review():
    t = RuleBasedTranslator()
    r = t.translate("ip route-static 10.0.0.0 255.0.0.0 192.168.0.1 preference 10 track 1\n", "huawei", "cisco")
    assert "ip route 10.0.0.0 255.0.0.0 192.168.0.1" in r
    assert "MANUAL_REVIEW" in r
    assert "preference" in r or "track" in r
    _check_no_source_residue(r, HUAWEI_KW)


def test_static_route_h3c_to_ruijie():
    t = RuleBasedTranslator()
    r = t.translate("ip route-static 10.0.0.0 255.0.0.0 192.168.0.1\n", "h3c", "ruijie")
    assert "ip route 10.0.0.0 255.0.0.0 192.168.0.1" in r
    _check_no_source_residue(r, H3C_KW)


def test_static_route_ruijie_to_h3c():
    t = RuleBasedTranslator()
    r = t.translate("ip route 10.0.0.0 255.0.0.0 192.168.0.1\n", "ruijie", "h3c")
    assert "ip route-static 10.0.0.0 255.0.0.0 192.168.0.1" in r
    _check_no_source_residue(r, RUIJIE_KW)


# ── OSPF ──

def test_ospf_cisco_to_huawei():
    t = RuleBasedTranslator()
    r = t.translate(
        "router ospf 10\n router-id 1.1.1.1\n network 10.0.0.0 0.255.255.255 area 0\n"
        " passive-interface default\n no passive-interface GigabitEthernet0/1\n",
        "cisco", "huawei",
    )
    assert "ospf 10" in r or "ospf 10 router-id" in r
    assert "router-id 1.1.1.1" in r
    assert "network 10.0.0.0 0.255.255.255 area 0" in r
    assert "silent-interface default" in r
    assert "undo silent-interface" in r
    _check_no_source_residue(r, CISCO_KW)


def test_ospf_huawei_to_cisco():
    t = RuleBasedTranslator()
    r = t.translate(
        "ospf 10\n router-id 1.1.1.1\n area 0.0.0.0\n  network 10.0.0.0 0.255.255.255\n"
        " silent-interface GigabitEthernet1/0/1\n",
        "huawei", "cisco",
    )
    assert "router ospf 10" in r
    assert "router-id 1.1.1.1" in r
    assert "area 0.0.0.0" in r
    assert "passive-interface GigabitEthernet1/0/1" in r
    _check_no_source_residue(r, HUAWEI_KW)


def test_ospf_h3c_to_ruijie():
    t = RuleBasedTranslator()
    r = t.translate("ospf 10\n router-id 2.2.2.2\n area 0\n  network 192.168.0.0 0.0.0.255\n", "h3c", "ruijie")
    assert "router ospf 10" in r
    assert "router-id 2.2.2.2" in r
    assert "area 0" in r
    assert "network 192.168.0.0 0.0.0.255" in r
    _check_no_source_residue(r, H3C_KW)


def test_ospf_ruijie_to_h3c():
    t = RuleBasedTranslator()
    r = t.translate("router ospf 10\n router-id 2.2.2.2\n network 192.168.0.0 0.0.0.255 area 0\n", "ruijie", "h3c")
    assert "ospf 10" in r
    assert "router-id 2.2.2.2" in r
    assert "network 192.168.0.0 0.0.0.255 area 0" in r
    _check_no_source_residue(r, RUIJIE_KW)


# ── BGP ──

def test_bgp_cisco_to_huawei():
    t = RuleBasedTranslator()
    r = t.translate(
        "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n network 172.16.0.0 mask 255.255.0.0\n",
        "cisco", "huawei",
    )
    assert "bgp 65001" in r
    assert "peer 10.0.0.2 as-number 65002" in r
    assert "network 172.16.0.0" in r
    assert "255.255.0.0" in r
    assert "ipv4-family unicast" in r
    _check_no_source_residue(r, CISCO_KW)


def test_bgp_huawei_to_cisco():
    t = RuleBasedTranslator()
    r = t.translate(
        "bgp 65001\n peer 10.0.0.2 as-number 65002\n network 10.0.0.0 mask 255.0.0.0\n",
        "huawei", "cisco",
    )
    assert "router bgp 65001" in r
    assert "neighbor 10.0.0.2 remote-as 65002" in r
    assert "network 10.0.0.0" in r
    _check_no_source_residue(r, HUAWEI_KW)


def test_bgp_description_manual_review():
    """BGP peer description/update-source must MANUAL_REVIEW."""
    t = RuleBasedTranslator()
    for frm, to in [("cisco","huawei"), ("huawei","cisco"), ("h3c","ruijie"), ("ruijie","h3c")]:
        r = t.translate(" neighbor 10.0.0.2 description WAN-LINK\n", frm, to)
        assert "MANUAL_REVIEW" in r, f"{frm}->{to}: BGP description should MANUAL_REVIEW"
        exe = _executable_lines(r)
        assert not any("neighbor" in x.lower() for x in exe), f"{frm}->{to}: neighbor leaked"


# ── VRF / VPN-instance ──

def test_vrf_cisco_to_huawei():
    t = RuleBasedTranslator()
    r = t.translate("vrf definition CUST-A\n rd 65001:100\n route-target both 65001:100\n", "cisco", "huawei")
    assert "ip vpn-instance CUST-A" in r
    assert "route-distinguisher 65001:100" in r
    assert "vpn-target" in r
    _check_no_source_residue(r, CISCO_KW)


def test_vrf_huawei_to_cisco():
    t = RuleBasedTranslator()
    r = t.translate("ip vpn-instance CUST-A\n route-distinguisher 65001:100\n vpn-target 65001:100 export-extcommunity\n", "huawei", "cisco")
    assert "vrf definition CUST-A" in r
    assert "rd 65001:100" in r
    assert "route-target" in r
    _check_no_source_residue(r, HUAWEI_KW)


def test_default_route_cisco_to_huawei():
    t = RuleBasedTranslator()
    r = t.translate("ip route 0.0.0.0 0.0.0.0 10.0.0.254\n", "cisco", "huawei")
    assert "ip route-static 0.0.0.0 0.0.0.0 10.0.0.254" in r
    _check_no_source_residue(r, CISCO_KW)


def test_default_route_huawei_to_cisco():
    t = RuleBasedTranslator()
    r = t.translate("ip route-static 0.0.0.0 0.0.0.0 10.0.0.254\n", "huawei", "cisco")
    assert "ip route 0.0.0.0 0.0.0.0 10.0.0.254" in r
    _check_no_source_residue(r, HUAWEI_KW)


def test_ospf_stub_area_manual_review():
    t = RuleBasedTranslator()
    r = t.translate("ospf 10\n area 0.0.0.1 stub\n", "huawei", "cisco")
    assert "area 0.0.0.1 stub" in r
    assert "MANUAL_REVIEW" in r, "stub area must produce MANUAL_REVIEW"


def test_bgp_password_manual_review():
    t = RuleBasedTranslator()
    r = t.translate("peer 10.1.1.2 password cipher TEST123\n", "huawei", "cisco")
    assert "MANUAL_REVIEW" in r, "BGP password must produce MANUAL_REVIEW"
    exe = _executable_lines(r)
    assert not any("password" in x.lower() and "TEST123" in x for x in exe), "BGP password must not leak"


# ── Negative tests: residue checker must reject source residue ──

def test_router_residue_checker_catches_source_eth_trunk():
    fake_output = "```huawei\neth-trunk 1\n```"
    with pytest.raises(AssertionError):
        _check_no_source_residue(fake_output, HUAWEI_KW)


def test_router_residue_checker_catches_source_aggregateport():
    fake_output = "```ruijie\nport-group 1 mode active\n```"
    with pytest.raises(AssertionError):
        _check_no_source_residue(fake_output, RUIJIE_KW)
