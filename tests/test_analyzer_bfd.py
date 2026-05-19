from __future__ import annotations
import pytest

from core.analyzers.bfd import BfdAnalyzer


def a(config_text: str, vendor: str = "cisco", domain: str = "routing", platform: str = "cisco_ios"):
    return BfdAnalyzer().analyze(config_text, vendor, domain, platform)


def test_huawei_named_bfd_session_full():
    config = """#
bfd BFD-PEER1 bind peer-ip 10.0.0.2
 discriminator local 100
 discriminator remote 200
 min-tx-interval 300
 min-rx-interval 300
 detect-multiplier 3
 bind source-ip 10.0.0.1
#
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert len(r.rules) == 1
    s = r.rules[0]
    assert s["session_name"] == "BFD-PEER1"
    assert s["peer_ip"] == "10.0.0.2"
    assert s["local_discriminator"] == "100"
    assert s["remote_discriminator"] == "200"
    assert s["min_tx"] == "300"
    assert s["min_rx"] == "300"
    assert s["multiplier"] == "3"
    assert s["source_ip"] == "10.0.0.1"
    assert r.risk_level == "info"


def test_huawei_ospf_bfd_enable():
    config = """#
ospf 1
 bfd enable
#
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert "ospf" in r.references.get("protocols", [])
    assert any("session 定义" in m for m in r.missing_context)


def test_huawei_bgp_peer_bfd():
    config = """#
bgp 65001
 peer 10.0.0.2 bfd
#
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert "bgp" in r.references.get("protocols", [])
    assert "10.0.0.2" in r.references.get("peer_ip", [])


def test_h3c_bfd_session_full():
    config = """#
bfd H3C-BFD bind peer-ip 192.168.1.2
 discriminator local 50
 discriminator remote 60
 min-tx-interval 200
 min-rx-interval 200
 detect-multiplier 5
#
"""
    r = a(config, "h3c")
    assert r.status == "analyzed"
    assert len(r.rules) == 1
    s = r.rules[0]
    assert s["session_name"] == "H3C-BFD"
    assert s["peer_ip"] == "192.168.1.2"
    assert s["min_tx"] == "200"
    assert s["multiplier"] == "5"
    assert r.risk_level == "info"


def test_cisco_interface_bfd_interval():
    config = """!
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.252
 bfd interval 300 min_rx 300 multiplier 3
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert len(r.rules) >= 1
    s = r.rules[0]
    assert s["min_tx"] == "300"
    assert s["min_rx"] == "300"
    assert s["multiplier"] == "3"
    assert s["binding"]["protocol"] == "interface"
    assert r.risk_level == "info"


def test_cisco_ospf_ip_ospf_bfd():
    config = """!
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.252
 ip ospf bfd
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert "ospf" in r.references.get("protocols", [])


def test_cisco_bgp_neighbor_fall_over_bfd():
    config = """!
router bgp 65001
 neighbor 10.0.0.2 fall-over bfd
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert "bgp" in r.references.get("protocols", [])
    assert "10.0.0.2" in r.references.get("peer_ip", [])


def test_missing_peer_ip_fatal():
    config = """#
bfd NO-PEER bind peer-ip
 discriminator local 100
#
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "fatal"
    assert any("peer-ip" in m for m in r.missing_context)


def test_bfd_session_no_peer_ip_is_fatal():
    config = """#
bfd NO-PEER bind peer-ip
#
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "fatal"


def test_bfd_referenced_but_no_session_warning():
    config = """!
router bgp 65001
 neighbor 10.0.0.2 fall-over bfd
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    assert any("被协议引用" in m for m in r.missing_context)


def test_non_bfd_skipped():
    config = """!
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.0
!
"""
    r = a(config, "cisco")
    assert r.status == "skipped"
