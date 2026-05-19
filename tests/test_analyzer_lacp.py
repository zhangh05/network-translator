from __future__ import annotations
import pytest

from core.analyzers.lacp import LacpAnalyzer


def a(config_text: str, vendor: str = "cisco", domain: str = "switching", platform: str = "cisco_ios"):
    return LacpAnalyzer().analyze(config_text, vendor, domain, platform)


def test_huawei_eth_trunk_full():
    config = """#
interface Eth-Trunk1
 mode lacp-static
 load-balance src-dst-ip
 lacp priority 100
 trunkport GigabitEthernet0/0/1
 trunkport GigabitEthernet0/0/2
#
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["aggregate_interface"] == "Eth-Trunk1"
    assert rule["group_id"] == "1"
    assert "lacp-static" in rule["mode"]
    assert len(rule["members"]) == 2
    assert "GigabitEthernet0/0/1" in rule["members"]
    assert "GigabitEthernet0/0/2" in rule["members"]
    assert rule["load_balance"] == "src-dst-ip"
    assert r.risk_level == "info"


def test_huawei_lacp_static():
    config = """!
interface Eth-Trunk2
 mode lacp-static
 trunkport GigabitEthernet0/0/3
!
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.rules[0]["mode"] == "lacp-static"
    assert r.risk_level == "info"


def test_h3c_bridge_aggregation():
    config = """#
interface Bridge-Aggregation1
 link-aggregation mode dynamic
 link-aggregation selected-port minimum 2
 lacp period short
#
interface GigabitEthernet1/0/1
 port link-aggregation group 1
#
interface GigabitEthernet1/0/2
 port link-aggregation group 1
#
"""
    r = a(config, "h3c")
    assert r.status == "analyzed"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["aggregate_interface"] == "Bridge-Aggregation1"
    assert rule["mode"] == "dynamic"
    assert rule["min_links"] == "2"
    assert rule["lacp_rate"] == "fast"
    assert len(rule["members"]) == 2
    assert "GigabitEthernet1/0/1" in rule["members"]
    assert r.risk_level == "info"


def test_cisco_port_channel_active():
    config = """!
interface Port-channel1
 port-channel load-balance src-dst-ip
!
interface GigabitEthernet0/0/1
 channel-group 1 mode active
 lacp port-priority 100
!
interface GigabitEthernet0/0/2
 channel-group 1 mode active
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["aggregate_interface"] == "Port-channel1"
    assert rule["group_id"] == "1"
    assert rule["mode"] == "active"
    assert len(rule["members"]) == 2
    assert rule["load_balance"] == "src-dst-ip"
    assert r.risk_level == "info"


def test_cisco_channel_group_on_is_manual():
    config = """!
interface Port-channel1
!
interface GigabitEthernet0/0/1
 channel-group 1 mode on
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.rules[0]["mode"] == "on"
    assert r.risk_level == "info"


def test_aggregate_no_members_warning():
    config = """!
interface Port-channel1
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    assert any("未发现成员" in m for m in r.missing_context)


def test_member_without_aggregate_warning():
    config = """!
interface GigabitEthernet0/0/1
 channel-group 1 mode active
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    assert any("未定义对应聚合接口" in m for m in r.missing_context) or any("未定义的聚合组" in m for m in r.missing_context)


def test_member_multiple_groups_fatal():
    config = """!
interface GigabitEthernet0/0/1
 channel-group 1 mode active
 channel-group 2 mode passive
!
interface Port-channel1
!
interface Port-channel2
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "fatal"
    assert any("多个聚合组" in m for m in r.missing_context)


def test_interface_range_warning():
    config = """!
interface range GigabitEthernet0/0/1-2
 channel-group 1 mode active
!
interface Port-channel1
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    assert any("interface range" in m for m in r.missing_context)


def test_non_lacp_skipped():
    config = """!
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.0
!
"""
    r = a(config, "cisco")
    assert r.status == "skipped"


def test_unsupported_vendor_skipped():
    config = """interface Port-channel1
 channel-group 1 mode active"""
    r = a(config, "ruijie")
    assert r.status == "skipped"
