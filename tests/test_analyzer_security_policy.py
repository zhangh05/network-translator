from core.analyzers.security_policy import SecurityPolicyAnalyzer

analyzer = SecurityPolicyAnalyzer()


def test_huawei_permit():
    cfg = """security-policy
 rule name permit-web
  source-zone trust
  destination-zone untrust
  source-address 192.168.1.0 mask 255.255.255.0
  destination-address 10.0.0.0 mask 255.255.255.0
  service http
  action permit
"""
    r = analyzer.analyze(cfg, "huawei", "firewall", "")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert r.rules[0]["action"] == "permit"
    assert r.rules[0]["source_zone"] == "trust"
    assert r.rules[0]["destination_zone"] == "untrust"
    assert "192.168.1.0" in r.rules[0]["source"]
    assert "http" in r.rules[0]["service"]


def test_huawei_deny():
    cfg = """security-policy
 rule name deny-all
  source-zone trust
  destination-zone untrust
  action deny
"""
    r = analyzer.analyze(cfg, "huawei", "firewall", "")
    assert r.rules[0]["action"] == "deny"


def test_h3c_security_policy_ip():
    cfg = """security-policy ip
 rule 10 name test-rule
  source-zone trust
  destination-zone untrust
  source-ip 192.168.1.0 255.255.255.0
  destination-ip 10.0.0.0 255.255.255.0
  service http
  action pass
"""
    r = analyzer.analyze(cfg, "h3c", "firewall", "")
    assert r.status == "analyzed"
    assert r.rules[0]["action"] == "permit"
    assert r.rules[0]["rule_id"] == "10"
    assert r.rules[0]["source_zone"] == "trust"
    assert r.rules[0]["destination_zone"] == "untrust"


def test_h3c_drop():
    cfg = """security-policy ip
 rule 20
  action drop
"""
    r = analyzer.analyze(cfg, "h3c", "firewall", "")
    assert r.rules[0]["action"] == "deny"


def test_cisco_asa_access_list():
    cfg = """object network WEB_SERVER
 host 203.0.113.10
!
access-list OUTSIDE extended permit tcp any object WEB_SERVER eq 80
access-group OUTSIDE in interface outside
"""
    r = analyzer.analyze(cfg, "cisco", "firewall", "asa")
    assert r.status == "analyzed"
    assert r.rules[0]["action"] == "permit"
    assert "203.0.113.10" in str(r.rules[0]["destination"])
    assert "80" in r.rules[0]["service"]
    assert r.rules[0]["source_zone"] == "outside"


def test_cisco_asa_host_literal():
    cfg = """access-list OUTSIDE extended permit tcp any host 203.0.113.10 eq 80
access-group OUTSIDE in interface outside
"""
    r = analyzer.analyze(cfg, "cisco", "firewall", "asa")
    assert "203.0.113.10" in str(r.rules[0]["destination"])


def test_reference_objects():
    cfg = """security-policy
 rule name obj-test
  source-zone trust
  destination-zone untrust
  source-address-set LAN_NET
  destination-address-set DMZ_NET
  service-set WEB_SVC
  action permit
"""
    r = analyzer.analyze(cfg, "huawei", "firewall", "")
    assert "LAN_NET" in r.rules[0]["source"]
    assert "DMZ_NET" in r.rules[0]["destination"]
    assert "WEB_SVC" in r.rules[0]["service"]


def test_missing_source_zone():
    cfg = """security-policy
 rule name bad-rule
  destination-zone untrust
  action permit
"""
    r = analyzer.analyze(cfg, "huawei", "firewall", "")
    assert r.risk_level in ("warning", "fatal")
    assert any("source-zone" in m for m in r.missing_context)


def test_non_security_policy_skipped():
    cfg = "interface GigabitEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n"
    r = analyzer.analyze(cfg, "huawei", "firewall", "")
    assert r.status == "skipped"
    assert r.risk_level == "info"


def test_huawei_source_addr_from_zone():
    cfg = """security-policy
 rule name zone-only
  source-zone trust
  destination-zone untrust
  action permit
"""
    r = analyzer.analyze(cfg, "huawei", "firewall", "")
    assert r.risk_level == "info"
    assert r.rules[0]["source_zone"] == "trust"
    assert r.rules[0]["destination_zone"] == "untrust"
    assert r.rules[0]["action"] == "permit"


def test_asa_access_group_out_direction():
    cfg = """access-list INSIDE extended permit ip 10.0.0.0 255.0.0.0 any
access-group INSIDE out interface inside
"""
    r = analyzer.analyze(cfg, "cisco", "firewall", "asa")
    assert r.status == "analyzed"
    assert r.rules[0]["source_zone"] == "any"
    assert r.rules[0]["destination_zone"] == "inside"
