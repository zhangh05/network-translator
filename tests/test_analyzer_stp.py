from __future__ import annotations
import pytest

from core.analyzers.stp import StpAnalyzer


def a(config_text: str, vendor: str = "cisco", domain: str = "switching", platform: str = "cisco_ios"):
    return StpAnalyzer().analyze(config_text, vendor, domain, platform)


def test_huawei_mstp_region_instance():
    config = """#
stp mode mstp
stp region-configuration
 instance 1 vlan 10 20-30
 active region-configuration
#
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["mode"] == "mstp"
    assert len(rule["instances"]) == 1
    inst = rule["instances"][0]
    assert inst["instance_id"] == "1"
    assert "10" in inst["vlans"]
    assert "20-30" in inst["vlans"]
    assert r.risk_level == "info"


def test_h3c_mstp_region_active():
    config = """#
stp mode mstp
stp region-configuration
 instance 1 vlan 10
 active region-configuration
#
"""
    r = a(config, "h3c")
    assert r.status == "analyzed"
    assert r.rules[0]["mode"] == "mstp"
    assert r.risk_level == "info"


def test_cisco_mst_configuration():
    config = """!
spanning-tree mode mst
spanning-tree mst configuration
 instance 1 vlan 10,20-30
 instance 2 vlan 40-50
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.rules[0]["mode"] == "mst"
    assert len(r.rules[0]["instances"]) == 2
    assert r.risk_level == "info"


def test_cisco_rapid_pvst():
    config = """!
spanning-tree mode rapid-pvst
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.rules[0]["mode"] == "rapid-pvst"
    assert r.risk_level == "info"


def test_root_primary_secondary():
    config = """!
spanning-tree vlan 10 root primary
spanning-tree vlan 20 root secondary
spanning-tree vlan 10 priority 4096
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    insts = {inst["instance_id"]: inst for inst in r.rules[0]["instances"]}
    assert insts["10"]["root_role"] == "primary"
    assert insts["20"]["root_role"] == "secondary"
    assert insts["10"]["priority"] == "4096"
    assert r.risk_level == "info"


def test_huawei_root_priority():
    config = """#
stp instance 1 root primary
stp instance 1 priority 4096
#
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    inst = r.rules[0]["instances"][0]
    assert inst["root_role"] == "primary"
    assert inst["priority"] == "4096"
    assert r.risk_level == "info"


def test_edge_and_bpdu_guard():
    config = """!
interface GigabitEthernet0/0/1
 spanning-tree portfast
 spanning-tree bpduguard enable
!
interface GigabitEthernet0/0/2
 spanning-tree portfast
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    ifaces = {i["interface"]: i for i in r.rules[0]["interfaces"]}
    assert ifaces["GigabitEthernet0/0/1"]["edge_port"] is True
    assert ifaces["GigabitEthernet0/0/1"]["bpdu_guard"] is True
    assert ifaces["GigabitEthernet0/0/2"]["edge_port"] is True
    assert r.risk_level == "info"


def test_root_guard():
    config = """!
interface GigabitEthernet0/0/1
 spanning-tree guard root
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    ifaces = {i["interface"]: i for i in r.rules[0]["interfaces"]}
    assert ifaces["GigabitEthernet0/0/1"]["root_guard"] is True
    assert r.risk_level == "info"


def test_huawei_edged_port_enable():
    config = """#
interface GigabitEthernet0/0/1
 stp edged-port enable
#
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    ifaces = {i["interface"]: i for i in r.rules[0]["interfaces"]}
    assert ifaces["GigabitEthernet0/0/1"]["edge_port"] is True
    assert r.risk_level == "info"


def test_region_without_active_warning():
    config = """!
spanning-tree mst configuration
 instance 1 vlan 10
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"


def test_mode_missing_warning():
    config = """!
stp bpdu-protection
!
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.rules[0]["mode"] == ""
    assert r.risk_level == "info"


def test_non_stp_skipped():
    config = """!
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.0
!
"""
    r = a(config, "cisco")
    assert r.status == "skipped"
