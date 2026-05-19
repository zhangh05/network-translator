"""Phase 5-B Step 30: DhcpAnalyzer — tests."""
import pytest
from core.analyzers.dhcp import DhcpAnalyzer

analyzer = DhcpAnalyzer()


def a(config: str, vendor: str = "huawei", domain: str = "routing", platform: str = "vrp"):
    return analyzer.analyze(config, vendor, domain, platform)


# ═══════════════════════════════════════════════════════════════════
# 1. Huawei ip pool 完整
# ═══════════════════════════════════════════════════════════════════

def test_huawei_pool_full():
    config = """#
dhcp enable
ip pool LAN
 network 192.168.10.0 mask 255.255.255.0
 gateway-list 192.168.10.1
 dns-list 8.8.8.8
 excluded-ip-address 192.168.10.1
 lease day 7
 option 66 ip 10.0.0.1
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["pool_name"] == "LAN"
    assert "192.168.10.0/255.255.255.0" in rule["network"]
    assert "192.168.10.1" in rule["gateway"]
    assert "8.8.8.8" in rule["dns"]
    assert "192.168.10.1" in rule["excluded"]
    assert rule["lease"] == "7"
    assert len(rule["options"]) == 1

# ═══════════════════════════════════════════════════════════════════
# 2. H3C dhcp server ip-pool 完整
# ═══════════════════════════════════════════════════════════════════

def test_h3c_pool_full():
    config = """#
dhcp enable
ip pool VLAN10
 network 10.0.10.0 mask 255.255.255.0
 gateway-list 10.0.10.1 10.0.10.2
 dns-list 8.8.8.8 4.4.4.4
#"""
    r = a(config, "h3c")
    assert r.status == "analyzed"
    # missing lease → warning by design
    assert r.risk_level == "warning"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["pool_name"] == "VLAN10"
    assert len(rule["gateway"]) == 2
    assert len(rule["dns"]) == 2

# ═══════════════════════════════════════════════════════════════════
# 3. Cisco ip dhcp pool 完整
# ═══════════════════════════════════════════════════════════════════

def test_cisco_pool_full():
    config = """!
service dhcp
ip dhcp pool LAN
 network 192.168.10.0 255.255.255.0
 default-router 192.168.10.1
 dns-server 8.8.8.8
 lease 7
 option 66 ip 10.0.0.1
!
ip dhcp excluded-address 192.168.10.1
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["pool_name"] == "LAN"
    assert "192.168.10.0/255.255.255.0" in rule["network"]
    assert "192.168.10.1" in rule["gateway"]
    assert "8.8.8.8" in rule["dns"]
    assert len(rule["options"]) == 1

# ═══════════════════════════════════════════════════════════════════
# 4. excluded-address / excluded-ip-address 提取
# ═══════════════════════════════════════════════════════════════════

def test_excluded_address():
    cfg_hw = """#
dhcp enable
ip pool TEST
 network 10.0.0.0 mask 255.255.255.0
 gateway-list 10.0.0.1
 excluded-ip-address 10.0.0.1
 excluded-ip-address 10.0.0.20 10.0.0.30
#"""
    r = a(cfg_hw, "huawei")
    assert r.status == "analyzed"
    assert "10.0.0.1" in r.rules[0]["excluded"]
    assert "10.0.0.20 10.0.0.30" in r.rules[0]["excluded"]

    cfg_c = """!
service dhcp
ip dhcp pool T
 network 10.0.0.0 255.255.255.0
 default-router 10.0.0.1
!
ip dhcp excluded-address 10.0.0.1
ip dhcp excluded-address 10.0.0.20 10.0.0.30
!"""
    r2 = a(cfg_c, "cisco")
    assert r2.status == "analyzed"
    assert "10.0.0.1" in r2.rules[0]["excluded"]

# ═══════════════════════════════════════════════════════════════════
# 5. interface dhcp select global/interface 提取
# ═══════════════════════════════════════════════════════════════════

def test_interface_dhcp_select():
    config = """#
dhcp enable
ip pool LAN
 network 192.168.10.0 mask 255.255.255.0
 gateway-list 192.168.10.1
#
interface Vlanif10
 ip address 192.168.10.1 255.255.255.0
 dhcp select global
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert len(r.rules) >= 2
    relay = next((x for x in r.rules if "Vlanif10" in str(x.get("interface_binding", ""))), None)
    assert relay is not None, f"Expected relay pool, got rules: {r.rules}"

# ═══════════════════════════════════════════════════════════════════
# 6. 缺 network → fatal
# ═══════════════════════════════════════════════════════════════════

def test_missing_network():
    config = """#
dhcp enable
ip pool BROKEN
 gateway-list 192.168.1.1
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "fatal"
    ctx = " ".join(r.missing_context)
    assert "network" in ctx and "fatal" in ctx

# ═══════════════════════════════════════════════════════════════════
# 7. 缺 gateway/default-router → Cisco warning, Huawei info
# ═══════════════════════════════════════════════════════════════════

def test_missing_gateway():
    cfg_hw = """#
dhcp enable
ip pool TEST
 network 10.0.0.0 mask 255.255.255.0
 dns-list 8.8.8.8
#"""
    r = a(cfg_hw, "huawei")
    assert r.status == "analyzed"
    # Huawei: no gateway warning
    assert r.risk_level == "warning"

    cfg_c = """!
service dhcp
ip dhcp pool TEST
 network 10.0.0.0 255.255.255.0
 dns-server 8.8.8.8
!"""
    r2 = a(cfg_c, "cisco")
    assert r2.status == "analyzed"
    assert r2.risk_level == "warning"
    ctx = " ".join(r2.missing_context)
    assert "default-router" in ctx

# ═══════════════════════════════════════════════════════════════════
# 8. option 提取
# ═══════════════════════════════════════════════════════════════════

def test_option_extraction():
    config = """#
dhcp enable
ip pool TEST
 network 10.0.0.0 mask 255.255.255.0
 gateway-list 10.0.0.1
 option 66 ip 10.0.0.100
 option 150 ip 10.0.0.200
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert len(r.rules[0]["options"]) == 2

# ═══════════════════════════════════════════════════════════════════
# 9. 非 DHCP 配置 skipped
# ═══════════════════════════════════════════════════════════════════

def test_non_dhcp_skipped():
    r = a("interface GigabitEthernet0/0/1\n ip address 10.0.0.1 255.255.255.0\n", "huawei")
    assert r.status == "skipped"

# ═══════════════════════════════════════════════════════════════════
# 10. Unsupported vendor skipped
# ═══════════════════════════════════════════════════════════════════

def test_unsupported_vendor_skipped():
    r = a("dhcp enable\nip pool TEST\n", "ruijie")
    assert r.status == "skipped"
