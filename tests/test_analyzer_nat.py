from core.analyzers.nat import NatAnalyzer

analyzer = NatAnalyzer()


def test_cisco_pat():
    cfg = """interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 ip nat inside
!
interface GigabitEthernet0/1
 ip address 203.0.113.1 255.255.255.0
 ip nat outside
!
access-list 10 permit 192.168.1.0 0.0.0.255
!
ip nat inside source list 10 interface GigabitEthernet0/1 overload
"""
    r = analyzer.analyze(cfg, "cisco", "routing", "ios")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert r.rules[0]["nat_type"] == "pat"
    assert r.rules[0]["references"]["acl"] == ["10"]
    assert r.rules[0]["egress_interface"] == "GigabitEthernet0/1"
    assert all("ACL 10" not in m for m in r.missing_context)


def test_cisco_static_nat():
    cfg = """interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 ip nat inside
!
interface GigabitEthernet0/1
 ip address 203.0.113.1 255.255.255.0
 ip nat outside
!
ip nat inside source static 10.0.0.10 203.0.113.10
"""
    r = analyzer.analyze(cfg, "cisco", "routing", "ios")
    assert r.status == "analyzed"
    assert r.rules[0]["nat_type"] == "static_nat"
    assert r.rules[0]["source"] == "10.0.0.10"
    assert r.rules[0]["translated_address"] == "203.0.113.10"


def test_huawei_nat_outbound():
    cfg = """acl number 3000
 rule 5 permit ip source 192.168.1.0 0.0.0.255
!
interface GigabitEthernet0/0/0
 ip address 203.0.113.1 255.255.255.0
 nat outbound 3000
"""
    r = analyzer.analyze(cfg, "huawei", "routing", "")
    assert r.status == "analyzed"
    assert r.rules[0]["nat_type"] in ("source_nat", "pat")
    assert r.rules[0]["references"]["acl"] == ["3000"]
    assert all("3000" not in m for m in r.missing_context)
    assert any("出接口" in m for m in r.missing_context)


def test_huawei_nat_server():
    cfg = """nat server protocol tcp global 1.1.1.1 80 inside 10.0.0.10 80
"""
    r = analyzer.analyze(cfg, "huawei", "routing", "")
    assert r.status == "analyzed"
    assert r.rules[0]["nat_type"] == "destination_nat"
    assert r.rules[0]["source"] == "10.0.0.10"
    assert r.rules[0]["destination"] == "1.1.1.1"


def test_firewall_nat_policy():
    cfg = """nat-policy
 rule 1
  source-zone trust
  destination-zone untrust
  action source-nat easy-ip
"""
    r = analyzer.analyze(cfg, "cisco", "firewall", "asa")
    assert r.status == "analyzed"
    assert r.rules[0]["nat_type"] == "source_nat"
    assert r.rules[0]["source_zone"] == "trust"
    assert r.rules[0]["destination_zone"] == "untrust"


def test_non_nat_config_skips():
    cfg = """interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
"""
    r = analyzer.analyze(cfg, "cisco", "routing", "ios")
    assert r.status == "skipped"
    assert r.risk_level == "info"


def test_h3c_nat_outbound():
    cfg = """acl advanced 3000
 rule 0 permit ip source 192.168.0.0 0.0.255.255
!
interface GigabitEthernet1/0/1
 port link-mode route
 nat outbound 3000
"""
    r = analyzer.analyze(cfg, "h3c", "routing", "")
    assert r.status == "analyzed"
    assert r.rules[0]["references"]["acl"] == ["3000"]
    assert r.rules[0]["nat_type"] in ("source_nat", "pat")


def test_firewall_policy_nat_with_references():
    cfg = """nat-policy
 rule 1
  source-zone trust
  destination-zone untrust
  address-set src_nat_pool
  service-set web_servers
  action source-nat easy-ip
"""
    r = analyzer.analyze(cfg, "huawei", "firewall", "")
    assert r.status == "analyzed"
    assert r.rules[0]["source_zone"] == "trust"
    assert r.rules[0]["destination_zone"] == "untrust"
    assert "src_nat_pool" in r.rules[0]["references"]["address_object"]
    assert "web_servers" in r.rules[0]["references"]["service_object"]


def test_huawei_nat_server_udp():
    cfg = """nat server protocol udp global 1.1.1.1 53 inside 10.0.0.53 53
"""
    r = analyzer.analyze(cfg, "huawei", "routing", "")
    assert r.status == "analyzed"
    assert r.rules[0]["nat_type"] == "destination_nat"
    assert r.rules[0]["service"] == "53"


def test_missing_acl_referenced():
    cfg = """ip nat inside source list 99 interface GigabitEthernet0/0 overload
"""
    r = analyzer.analyze(cfg, "cisco", "routing", "ios")
    assert r.status == "analyzed"
    assert any("ACL 99" in m for m in r.missing_context), f"Missing: {r.missing_context}"


def test_cisco_outside_nat():
    cfg = """ip nat outside source static 203.0.113.10 10.0.0.10
"""
    r = analyzer.analyze(cfg, "cisco", "routing", "ios")
    assert r.status == "analyzed"
    assert r.rules[0]["nat_type"] == "source_nat"
