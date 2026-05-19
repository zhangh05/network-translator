from core.analyzers.acl import AclAnalyzer

analyzer = AclAnalyzer()


def test_cisco_standard_acl():
    r = analyzer.analyze(
        "access-list 10 permit 10.0.0.0 0.0.0.255",
        "cisco", "routing", "",
    )
    assert r.status == "analyzed"
    assert r.rules[0]["action"] == "permit"
    assert "10.0.0.0" in r.rules[0]["source"]
    assert r.rules[0]["protocol"] == "ip"


def test_cisco_extended_acl():
    r = analyzer.analyze(
        "access-list 101 permit tcp any host 1.1.1.1 eq 80",
        "cisco", "routing", "",
    )
    assert r.status == "analyzed"
    assert r.rules[0]["action"] == "permit"
    assert r.rules[0]["protocol"] == "tcp"
    assert r.rules[0]["destination_port"] == "80"
    assert "1.1.1.1" in r.rules[0]["destination"]


def test_cisco_named_acl():
    cfg = """ip access-list extended WEB
 permit tcp any host 1.1.1.1 eq 443
 permit udp any host 1.1.1.1 eq 53
"""
    r = analyzer.analyze(cfg, "cisco", "routing", "")
    assert r.status == "analyzed"
    assert r.rules[0]["acl_name"] == "WEB"
    assert r.rules[0]["action"] == "permit"
    assert r.rules[0]["destination_port"] == "443"
    assert len(r.rules) == 2
    assert "WEB" in r.metadata["acl_names"]


def test_huawei_acl_number():
    cfg = """acl number 3000
 rule 5 permit ip source 10.0.0.0 0.0.0.255 destination any
"""
    r = analyzer.analyze(cfg, "huawei", "routing", "")
    assert r.status == "analyzed"
    assert r.rules[0]["rule_id"] == "5"
    assert r.rules[0]["action"] == "permit"
    assert "10.0.0.0" in r.rules[0]["source"]
    assert r.rules[0]["acl_id"] == "3000"


def test_huawei_deny_rule():
    cfg = """acl number 3001
 rule 10 deny tcp source any destination 1.1.1.1 0 destination-port eq 22
"""
    r = analyzer.analyze(cfg, "huawei", "routing", "")
    assert r.status == "analyzed"
    assert r.rules[0]["action"] == "deny"
    assert r.rules[0]["protocol"] == "tcp"
    assert r.rules[0]["destination_port"] == "22"
    assert "1.1.1.1" in r.rules[0]["destination"]


def test_h3c_acl():
    cfg = """acl number 3002
 rule 5 permit ip source 192.168.0.0 0.0.255.255 destination any
"""
    r = analyzer.analyze(cfg, "h3c", "routing", "")
    assert r.status == "analyzed"
    assert r.rules[0]["acl_id"] == "3002"
    assert r.rules[0]["action"] == "permit"


def test_non_acl_config_skipped():
    cfg = "interface GigabitEthernet0/0\n ip address 1.1.1.1 255.255.255.0\n"
    r = analyzer.analyze(cfg, "cisco", "routing", "")
    assert r.status == "skipped"
    assert r.risk_level == "info"


def test_huawei_deny_icmp():
    cfg = """acl number 3003
 rule 15 deny icmp source 10.0.0.0 0.0.0.255 destination any
"""
    r = analyzer.analyze(cfg, "huawei", "routing", "")
    assert r.rules[0]["action"] == "deny"
    assert r.rules[0]["protocol"] == "icmp"


def test_cisco_named_acl_multiple_entries():
    cfg = """ip access-list extended FILTER
 permit tcp any host 10.0.0.1 eq 443
 deny tcp any host 10.0.0.1 eq 22
 permit ip any any
"""
    r = analyzer.analyze(cfg, "cisco", "routing", "")
    assert len(r.rules) == 3
    assert r.rules[0]["destination_port"] == "443"
    assert r.rules[1]["action"] == "deny"
    assert r.rules[2]["protocol"] == "ip"


def test_cisco_extended_with_obj_group():
    cfg = """object-group network SRV
  network 10.0.0.0 255.255.255.0
access-list 101 permit tcp any object-group SRV eq 8080
"""
    r = analyzer.analyze(cfg, "cisco", "routing", "")
    assert r.status == "analyzed"
    assert "SRV" in r.rules[0]["references"]["object_group"]
