"""Phase 5-C Step 31: VrfAnalyzer — tests."""
import pytest
from core.analyzers.vrf import VrfAnalyzer

analyzer = VrfAnalyzer()


def a(config: str, vendor: str = "huawei", domain: str = "routing", platform: str = "vrp"):
    return analyzer.analyze(config, vendor, domain, platform)


# ═══════════════════════════════════════════════════════════════════
# 1. Huawei vpn-instance 完整
# ═══════════════════════════════════════════════════════════════════

def test_huawei_vpn_instance_full():
    config = """#
ip vpn-instance CUST_A
 route-distinguisher 65000:1
 vpn-target 65000:1 import-extcommunity
 vpn-target 65000:1 export-extcommunity
#
interface GigabitEthernet0/0/1
 ip binding vpn-instance CUST_A
 ip address 10.0.0.1 255.255.255.0
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["vrf_name"] == "CUST_A"
    assert rule["rd"] == "65000:1"
    assert "65000:1" in rule["route_targets"]["import"]
    assert "65000:1" in rule["route_targets"]["export"]
    assert "GigabitEthernet0/0/1" in rule["bound_interfaces"]

# ═══════════════════════════════════════════════════════════════════
# 2. H3C vpn-instance 完整
# ═══════════════════════════════════════════════════════════════════

def test_h3c_vpn_instance_full():
    config = """#
ip vpn-instance VPN_B
 route-distinguisher 65001:100
 vpn-target 65001:100 both
#
interface GigabitEthernet1/0/1
 ip binding vpn-instance VPN_B
#"""
    r = a(config, "h3c")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    rule = r.rules[0]
    assert rule["vrf_name"] == "VPN_B"
    assert "65001:100" in rule["route_targets"]["import"]
    assert "65001:100" in rule["route_targets"]["export"]

# ═══════════════════════════════════════════════════════════════════
# 3. Cisco vrf definition 完整
# ═══════════════════════════════════════════════════════════════════

def test_cisco_vrf_definition_full():
    config = """!
vrf definition CUST_C
 rd 65002:1
 route-target import 65002:1
 route-target export 65002:1
 address-family ipv4
 exit-address-family
!
interface GigabitEthernet0/1
 vrf forwarding CUST_C
 ip address 192.168.1.1 255.255.255.0
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["vrf_name"] == "CUST_C"
    assert rule["rd"] == "65002:1"
    assert "65002:1" in rule["route_targets"]["import"]
    assert "65002:1" in rule["route_targets"]["export"]
    assert "GigabitEthernet0/1" in rule["bound_interfaces"]

# ═══════════════════════════════════════════════════════════════════
# 4. Interface binding 提取
# ═══════════════════════════════════════════════════════════════════

def test_interface_binding():
    config = """#
ip vpn-instance MULTI
 route-distinguisher 65003:1
 vpn-target 65003:1 both
#
interface GigabitEthernet0/0/1
 ip binding vpn-instance MULTI
interface GigabitEthernet0/0/2
 ip binding vpn-instance MULTI
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    rule = r.rules[0]
    assert len(rule["bound_interfaces"]) == 2
    assert "GigabitEthernet0/0/1" in rule["bound_interfaces"]
    assert "GigabitEthernet0/0/2" in rule["bound_interfaces"]

# ═══════════════════════════════════════════════════════════════════
# 5. Interface 引用未定义 VRF → fatal
# ═══════════════════════════════════════════════════════════════════

def test_undefined_vrf_binding():
    config = """#
interface GigabitEthernet0/0/1
 ip binding vpn-instance UNDEFINED_VRF
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "fatal"
    ctx = " ".join(r.missing_context)
    assert "UNDEFINED_VRF" in ctx and "fatal" in ctx

# ═══════════════════════════════════════════════════════════════════
# 6. 缺 rd 或 route-target → warning
# ═══════════════════════════════════════════════════════════════════

def test_missing_rd_rt():
    config = """#
ip vpn-instance INCOMPLETE
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    ctx = " ".join(r.missing_context)
    assert "route-distinguisher" in ctx
    assert "route-target" in ctx

# ═══════════════════════════════════════════════════════════════════
# 7. 非 VRF 配置 skipped
# ═══════════════════════════════════════════════════════════════════

def test_non_vrf_skipped():
    r = a("interface GigabitEthernet0/0/1\n ip address 10.0.0.1 255.255.255.0\n", "huawei")
    assert r.status == "skipped"

# ═══════════════════════════════════════════════════════════════════
# 8. Unsupported vendor skipped
# ═══════════════════════════════════════════════════════════════════

def test_unsupported_vendor_skipped():
    r = a("ip vpn-instance TEST\n", "ruijie")
    assert r.status == "skipped"

# ═══════════════════════════════════════════════════════════════════
# 9. VRF 定义了但未绑定接口 → warning
# ═══════════════════════════════════════════════════════════════════

def test_vrf_no_binding():
    config = """#
ip vpn-instance ORPHAN
 route-distinguisher 65004:1
 vpn-target 65004:1 both
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    ctx = " ".join(r.missing_context)
    assert "未绑定" in ctx

# ═══════════════════════════════════════════════════════════════════
# 10. Multiple VRFs
# ═══════════════════════════════════════════════════════════════════

def test_multiple_vrfs():
    config = """#
ip vpn-instance VRF_A
 route-distinguisher 65001:1
 vpn-target 65001:1 both
#
ip vpn-instance VRF_B
 route-distinguisher 65002:1
 vpn-target 65002:1 both
#
interface GigabitEthernet0/0/1
 ip binding vpn-instance VRF_A
interface GigabitEthernet0/0/2
 ip binding vpn-instance VRF_B
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 2
