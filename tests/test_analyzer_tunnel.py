from __future__ import annotations
import pytest

from core.analyzers.tunnel import TunnelAnalyzer


def a(config_text: str, vendor: str = "cisco", domain: str = "routing", platform: str = "cisco_ios"):
    return TunnelAnalyzer().analyze(config_text, vendor, domain, platform)


def test_huawei_gre_tunnel_full():
    config = """#
interface Tunnel0/0/1
 tunnel-protocol gre
 source LoopBack0
 destination 203.0.113.1
 ip address 10.0.0.1 255.255.255.252
 gre key 100
 keepalive
#
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["interface"] == "Tunnel0/0/1"
    assert rule["tunnel_type"] == "gre"
    assert rule["source"] == "LoopBack0"
    assert rule["destination"] == "203.0.113.1"
    assert rule["ip_address"] == "10.0.0.1/255.255.255.252"
    assert rule["key"] == "100"
    assert rule["keepalive"] is True
    assert rule["vrf"] == ""
    assert r.risk_level == "info"


def test_h3c_gre_tunnel_full():
    config = """#
interface Tunnel1
 tunnel-protocol gre
 source GigabitEthernet0/0/1
 destination 198.51.100.2
 ip address 172.16.0.1 255.255.255.252
 keepalive
#
"""
    r = a(config, "h3c")
    assert r.status == "analyzed"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["interface"] == "Tunnel1"
    assert rule["tunnel_type"] == "gre"
    assert rule["source"] == "GigabitEthernet0/0/1"
    assert rule["destination"] == "198.51.100.2"
    assert rule["keepalive"] is True
    assert r.risk_level == "info"


def test_cisco_gre_tunnel_full():
    config = """!
interface Tunnel0
 tunnel mode gre ip
 tunnel source Loopback0
 tunnel destination 203.0.113.1
 ip address 10.0.0.1 255.255.255.252
 tunnel key 100
 keepalive
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["interface"] == "Tunnel0"
    assert rule["tunnel_type"] == "gre"
    assert rule["source"] == "Loopback0"
    assert rule["destination"] == "203.0.113.1"
    assert rule["key"] == "100"
    assert rule["keepalive"] is True
    assert r.risk_level == "info"


def test_cisco_ipip_tunnel():
    config = """!
interface Tunnel0
 tunnel mode ipip
 tunnel source 192.0.2.1
 tunnel destination 198.51.100.1
 ip address 10.0.0.1 255.255.255.252
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert len(r.rules) == 1
    assert r.rules[0]["tunnel_type"] == "ipip"
    assert r.risk_level == "info"


def test_missing_source_fatal():
    config = """!
interface Tunnel0
 tunnel mode gre ip
 tunnel destination 203.0.113.1
 ip address 10.0.0.1 255.255.255.252
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "fatal"
    assert any("source" in m for m in r.missing_context)


def test_missing_destination_fatal():
    config = """!
interface Tunnel0
 tunnel mode gre ip
 tunnel source Loopback0
 ip address 10.0.0.1 255.255.255.252
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "fatal"
    assert any("destination" in m for m in r.missing_context)


def test_vrf_binding():
    config = """!
interface Tunnel0
 tunnel mode gre ip
 tunnel source Loopback0
 tunnel destination 203.0.113.1
 ip address 10.0.0.1 255.255.255.252
 tunnel vrf CUST_A
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.rules[0]["vrf"] == "CUST_A"
    assert "CUST_A" in r.references.get("vrf", [])
    assert r.risk_level == "info"


def test_huawei_vpn_binding():
    config = """#
interface Tunnel0/0/1
 tunnel-protocol gre
 source LoopBack0
 destination 203.0.113.1
 ip address 10.0.0.1 255.255.255.252
 ip binding vpn-instance CUST_B
#
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.rules[0]["vrf"] == "CUST_B"
    assert "CUST_B" in r.references.get("vrf", [])
    assert r.risk_level == "info"


def test_ipsec_tunnel_triggers_warning():
    config = """!
interface Tunnel0
 tunnel mode gre ip
 tunnel source Loopback0
 tunnel destination 203.0.113.1
 ip address 10.0.0.1 255.255.255.252
 tunnel vrf CUST_A
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "info"

    config2 = """#
interface Tunnel0/0/1
 tunnel-protocol ipsec
 source LoopBack0
 destination 203.0.113.1
 ip address 10.0.0.1 255.255.255.252
#
"""
    r2 = a(config2, "huawei")
    assert r2.status == "analyzed"
    assert r2.risk_level == "warning"
    assert r2.manual_review_required is True
    assert any("IpsecAnalyzer" in m for m in r2.missing_context)


def test_non_tunnel_skipped():
    config = """!
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.0
!
"""
    r = a(config, "cisco")
    assert r.status == "skipped"


def test_unsupported_vendor_skipped():
    config = """!
interface Tunnel0
 tunnel mode gre ip
 tunnel source Loopback0
 tunnel destination 203.0.113.1
!
"""
    r = a(config, "ruijie")
    assert r.status == "skipped"


def test_source_interface_reference():
    config = """!
interface Tunnel0
 tunnel mode gre ip
 tunnel source GigabitEthernet0/0/1
 tunnel destination 203.0.113.1
 ip address 10.0.0.1 255.255.255.252
!
"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert "GigabitEthernet0/0/1" in r.references.get("source_interface", [])
