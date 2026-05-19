"""Phase 5-B Step 29: VrrpAnalyzer — tests."""
import pytest
from core.analyzers.vrrp import VrrpAnalyzer

analyzer = VrrpAnalyzer()


def a(config: str, vendor: str = "huawei", domain: str = "routing", platform: str = "vrp"):
    return analyzer.analyze(config, vendor, domain, platform)


# ═══════════════════════════════════════════════════════════════════
# 1. Huawei VRRP full — interface + vrid + vip + priority + preempt + track
# ═══════════════════════════════════════════════════════════════════

def test_huawei_vrrp_full():
    config = """#
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.0
 vrrp vrid 10 virtual-ip 192.168.1.1
 vrrp vrid 10 priority 120
 vrrp vrid 10 preempt-mode
 vrrp vrid 10 track interface GigabitEthernet0/0/2
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["group_id"] == "10"
    assert rule["interface"] == "GigabitEthernet0/0/1"
    assert rule["virtual_ip"] == "192.168.1.1"
    assert rule["priority"] == "120"
    assert rule["preempt"] is True
    assert rule["track"] == ["GigabitEthernet0/0/2"]

# ═══════════════════════════════════════════════════════════════════
# 2. H3C VRRP full
# ═══════════════════════════════════════════════════════════════════

def test_h3c_vrrp_full():
    config = """#
interface GigabitEthernet1/0/1
 ip address 10.0.1.1 255.255.255.0
 vrrp vrid 20 virtual-ip 192.168.2.1
 vrrp vrid 20 priority 150
 vrrp vrid 20 preempt-mode timer delay 30
 vrrp vrid 20 track bfd BFD1
#"""
    r = a(config, "h3c")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["group_id"] == "20"
    assert rule["interface"] == "GigabitEthernet1/0/1"
    assert rule["virtual_ip"] == "192.168.2.1"
    assert "bfd:BFD1" in rule["track"]

# ═══════════════════════════════════════════════════════════════════
# 3. Cisco HSRP full
# ═══════════════════════════════════════════════════════════════════

def test_cisco_hsrp_full():
    config = """!
interface GigabitEthernet0/1
 ip address 10.0.0.2 255.255.255.0
 standby 10 ip 192.168.1.1
 standby 10 priority 120
 standby 10 preempt
 standby 10 track GigabitEthernet0/2
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["group_id"] == "10"
    assert rule["interface"] == "GigabitEthernet0/1"
    assert rule["virtual_ip"] == "192.168.1.1"
    assert rule["priority"] == "120"
    assert rule["preempt"] is True
    assert rule["track"] == ["GigabitEthernet0/2"]

# ═══════════════════════════════════════════════════════════════════
# 4. 缺 virtual-ip → fatal
# ═══════════════════════════════════════════════════════════════════

def test_missing_virtual_ip():
    config = """#
interface GigabitEthernet0/0/1
 vrrp vrid 10 priority 100
 vrrp vrid 10 preempt-mode
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "fatal"
    ctx = " ".join(r.missing_context)
    assert "virtual-ip" in ctx and "fatal" in ctx

# ═══════════════════════════════════════════════════════════════════
# 5. 缺 interface 上下文
# ═══════════════════════════════════════════════════════════════════

def test_vrrp_outside_interface():
    config = "vrrp vrid 10 virtual-ip 192.168.1.1\n"
    r = a(config, "huawei")
    assert r.status == "skipped"

# ═══════════════════════════════════════════════════════════════════
# 6. Track interface 提取
# ═══════════════════════════════════════════════════════════════════

def test_vrrp_track_extraction():
    config = """#
interface GigabitEthernet0/0/1
 vrrp vrid 30 virtual-ip 10.0.0.1
 vrrp vrid 30 track interface GigabitEthernet0/0/2
 vrrp vrid 30 track interface GigabitEthernet0/0/3
 vrrp vrid 30 track bfd BFD_SESSION
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    rule = r.rules[0]
    assert len(rule["track"]) == 3
    assert "GigabitEthernet0/0/2" in rule["track"]
    assert "GigabitEthernet0/0/3" in rule["track"]
    assert "bfd:BFD_SESSION" in rule["track"]

# ═══════════════════════════════════════════════════════════════════
# 7. 非 VRRP 配置 skipped
# ═══════════════════════════════════════════════════════════════════

def test_non_vrrp_skipped():
    r = a("interface GigabitEthernet0/0/1\n ip address 10.0.0.1 255.255.255.0\n", "huawei")
    assert r.status == "skipped"

# ═══════════════════════════════════════════════════════════════════
# 8. Unsupported vendor skipped
# ═══════════════════════════════════════════════════════════════════

def test_unsupported_vendor_skipped():
    r = a("vrrp vrid 10 virtual-ip 10.0.0.1\n", "ruijie")
    assert r.status == "skipped"

# ═══════════════════════════════════════════════════════════════════
# 9. Multiple VRRP groups on different interfaces
# ═══════════════════════════════════════════════════════════════════

def test_multiple_vrrp_groups():
    config = """#
interface GigabitEthernet0/0/1
 vrrp vrid 10 virtual-ip 192.168.1.1
 vrrp vrid 10 priority 110
#
interface GigabitEthernet0/0/2
 vrrp vrid 20 virtual-ip 192.168.2.1
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 2
    g10 = next(x for x in r.rules if x["group_id"] == "10")
    g20 = next(x for x in r.rules if x["group_id"] == "20")
    assert g10["interface"] == "GigabitEthernet0/0/1"
    assert g20["interface"] == "GigabitEthernet0/0/2"
    assert g10["virtual_ip"] == "192.168.1.1"
    assert g20["virtual_ip"] == "192.168.2.1"
    assert g10["priority"] == "110"

# ═══════════════════════════════════════════════════════════════════
# 10. Cisco HSRP multiple groups
# ═══════════════════════════════════════════════════════════════════

def test_cisco_multiple_hsrp():
    config = """!
interface Vlan10
 standby 10 ip 192.168.10.1
 standby 10 priority 100
!
interface Vlan20
 standby 20 ip 192.168.20.1
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 2
