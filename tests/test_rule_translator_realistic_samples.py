# -*- coding: utf-8 -*-
"""Realistic end-to-end configuration samples for fallback translator validation.

Each sample is a small but realistic multi-line config from a common user scenario.
Samples are designed to exercise the full translation path and verify:
1. Key target commands are present
2. MANUAL_REVIEW is emitted for uncertain items
3. No source vendor executable keywords leak into output
4. Output is non-empty and fenced with correct vendor tag
"""

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
        if line.startswith("#") or line.startswith("!"):
            continue
        lines.append(line)
    return lines


def _check_no_source_residue(result, keywords):
    exe = _executable_lines(result)
    for kw in keywords:
        nkw = kw.lower()
        for line in exe:
            assert nkw not in line.lower(), f"Source residue '{kw}' in executable line: {line}"


# ── Sample 1: Huawei VRP SWITCH → Cisco ──
def test_huawei_vrp_switch_to_cisco():
    config = """sysname SW-CORE-01
vlan batch 10 20 30
interface XGigabitEthernet0/0/1
 port link-type trunk
 port trunk allow-pass vlan 10 20 30
interface XGigabitEthernet0/0/2
 eth-trunk 1
interface Vlanif10
 ip address 172.16.10.1 255.255.255.0
ip route-static 0.0.0.0 0.0.0.0 172.16.10.254
stp edged-port enable
spanning-tree bpduguard enable
"""
    t = RuleBasedTranslator()
    r = t.translate(config, "huawei", "cisco")
    exe = _executable_lines(r)

    assert r.startswith("```cisco"), f"Wrong fence: {r[:20]}"
    assert "hostname SW-CORE-01" in r
    assert "vlan 10" in r
    assert "interface TenGigabitEthernet0/0/1" in r
    assert "interface TenGigabitEthernet0/0/2" in r
    assert "switchport mode trunk" in r
    assert "switchport trunk allowed vlan" in r
    assert "channel-group 1 mode active" in r
    assert "interface Vlan10" in r
    assert "ip address 172.16.10.1 255.255.255.0" in r
    assert "ip route 0.0.0.0 0.0.0.0 172.16.10.254" in r
    assert "spanning-tree portfast" in r
    assert "MANUAL_REVIEW" in r, "spanning-tree bpduguard must produce MANUAL_REVIEW"
    _check_no_source_residue(r, HUAWEI_KW)


# ── Sample 2: H3C SWITCH → Cisco ──
def test_h3c_switch_to_cisco():
    config = """sysname SW-DMZ
vlan 10
vlan 10 to 20
interface GigabitEthernet1/0/1
 port link-type trunk
 port trunk permit vlan 10 20
interface Vlan-interface10
 ip address 10.0.10.1 255.255.255.0
 undo shutdown
packet-filter 3000
"""
    t = RuleBasedTranslator()
    r = t.translate(config, "h3c", "cisco")
    exe = _executable_lines(r)

    assert r.startswith("```cisco"), f"Wrong fence: {r[:20]}"
    assert "hostname SW-DMZ" in r
    assert "vlan" in r
    assert "interface GigabitEthernet1/0/1" in r
    assert "switchport mode trunk" in r
    assert "interface Vlan10" in r
    assert "ip address 10.0.10.1 255.255.255.0" in r
    assert "no shutdown" in r
    assert "MANUAL_REVIEW" in r, "packet-filter must produce MANUAL_REVIEW"
    _check_no_source_residue(r, H3C_KW)


# ── Sample 3: Cisco SWITCH → Huawei ──
def test_cisco_switch_to_huawei():
    config = """hostname SW-ACCESS
vlan 10
vlan 10,20,30
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30-32
interface Port-channel1
 switchport mode trunk
 switchport trunk allowed vlan 10,20
channel-group 1 mode active
interface Vlan10
 ip address 192.168.10.1 255.255.255.0
 no shutdown
spanning-tree bpduguard enable
"""
    t = RuleBasedTranslator()
    r = t.translate(config, "cisco", "huawei")
    exe = _executable_lines(r)

    assert r.startswith("```huawei"), f"Wrong fence: {r[:20]}"
    assert "sysname SW-ACCESS" in r
    assert "vlan batch" in r
    assert "interface GigabitEthernet0/1" in r
    assert "port link-type trunk" in r
    assert "eth-trunk 1" in r
    assert "interface Vlanif10" in r
    assert "ip address 192.168.10.1 255.255.255.0" in r
    assert "undo shutdown" in r
    assert "MANUAL_REVIEW" in r, "spanning-tree bpduguard must produce MANUAL_REVIEW"
    _check_no_source_residue(r, CISCO_KW)


# ── Sample 4: Cisco ROUTER → Huawei ──
def test_cisco_router_to_huawei():
    config = """router ospf 10
 router-id 10.0.0.1
 passive-interface default
 no passive-interface GigabitEthernet0/1
network 10.0.0.0 0.0.0.255 area 0
ip route 0.0.0.0 0.0.0.0 10.0.0.254 track 1
router bgp 65001
 neighbor 10.1.1.2 remote-as 65002
 neighbor 10.1.1.2 route-map RM-IN in
"""
    t = RuleBasedTranslator()
    r = t.translate(config, "cisco", "huawei")
    exe = _executable_lines(r)

    assert r.startswith("```huawei"), f"Wrong fence: {r[:20]}"
    assert "ospf 10" in r
    assert "router-id 10.0.0.1" in r
    assert "silent-interface default" in r
    assert "undo silent-interface gigabitethernet0/1" in r
    assert "network 10.0.0.0 0.0.0.255 area 0" in r
    assert "ip route-static 0.0.0.0 0.0.0.0 10.0.0.254" in r
    assert "MANUAL_REVIEW" in r, "track option must produce MANUAL_REVIEW"
    assert "bgp 65001" in r
    assert "peer 10.1.1.2 as-number 65002" in r
    assert "MANUAL_REVIEW" in r, "route-map must produce MANUAL_REVIEW"
    _check_no_source_residue(r, CISCO_KW)


# ── Sample 5: Huawei ROUTER → Cisco ──
def test_huawei_router_to_cisco():
    config = """ospf 10
 router-id 1.1.1.1
 area 0.0.0.0
  network 10.0.0.0 0.0.0.255
 silent-interface GigabitEthernet1/0/1
bgp 65001
 peer 10.1.1.2 as-number 65002
filter-policy PFXLIST-ONE export
ip vpn-instance CUST-A
 route-distinguisher 65001:100
 vpn-target 65001:100 export-extcommunity
"""
    t = RuleBasedTranslator()
    r = t.translate(config, "huawei", "cisco")
    exe = _executable_lines(r)

    assert r.startswith("```cisco"), f"Wrong fence: {r[:20]}"
    assert "router ospf 10" in r
    assert "router-id 1.1.1.1" in r
    assert "area 0.0.0.0" in r
    assert "passive-interface GigabitEthernet1/0/1" in r
    assert "router bgp 65001" in r
    assert "neighbor 10.1.1.2 remote-as 65002" in r
    assert "MANUAL_REVIEW" in r, "filter-policy must produce MANUAL_REVIEW"
    assert "vrf definition CUST-A" in r
    assert "rd 65001:100" in r
    assert "route-target" in r
    _check_no_source_residue(r, HUAWEI_KW)


# ── Sample 6: Huawei USG FIREWALL → Hillstone ──
def test_huawei_usg_firewall_to_hillstone():
    config = """security-zone name trust
 add interface GigabitEthernet0/0
ip address-set CUST-LAN type object
 address 0 192.168.100.0 mask 24
ip address-set SRV-NET type object
 address 0 10.0.0.0 mask 24
ip service-set WEB-SVC type object
 service 0 protocol tcp destination-port 80
 service 1 protocol tcp destination-port 443
security-policy
 rule name POL-WAN-TO-LAN
  source-zone wan
  destination-zone trust
  source-address 0.0.0.0 mask 0.0.0.0
  destination-address CUST-LAN
  service WEB-SVC
  action permit
 time-range WORK-HOURS
  periodic start 09:00 2026-01-01 end 18:00 2026-12-31
"""
    t = RuleBasedTranslator()
    r = t.translate(config, "huawei_usg", "hillstone")
    exe = _executable_lines(r)

    assert r.startswith("```hillstone"), f"Wrong fence: {r[:20]}"
    assert "zone trust" in r
    assert "MANUAL_REVIEW" in r, "zone interface binding must produce MANUAL_REVIEW"
    assert "address CUST-LAN 192.168.100.0 255.255.255.0" in r
    assert "address SRV-NET 10.0.0.0 255.255.255.0" in r
    assert "service WEB-SVC tcp dst-port 80" in r
    assert "policy POL-WAN-TO-LAN" in r
    assert "MANUAL_REVIEW" in r, "time-range must produce MANUAL_REVIEW"
    assert not any("security-policy" in x.lower() for x in exe), "security-policy source must not leak"
    _check_no_source_residue(r, ["security-zone", "security-policy", "ip address-set", "ip service-set"])