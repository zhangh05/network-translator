"""Phase 5-A Step 27: QosAnalyzer — tests."""
import pytest
from core.analyzers.qos import QosAnalyzer

analyzer = QosAnalyzer()


def a(config: str, vendor: str = "huawei", domain: str = "routing", platform: str = "vrp"):
    return analyzer.analyze(config, vendor, domain, platform)


# ═══════════════════════════════════════════════════════════════════
# 1. Huawei full classifier + behavior + policy + interface binding
# ═══════════════════════════════════════════════════════════════════

def test_huawei_qos_full():
    config = """#
traffic classifier VOICE
 if-match acl 3000
 if-match dscp ef
#
traffic behavior VOICE-BEH
 car cir 10000
 remark dscp ef
 priority 5
#
traffic policy QOS-IN
 classifier VOICE behavior VOICE-BEH precedence 5
#
interface GigabitEthernet0/0/1
 traffic-policy QOS-IN inbound
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert not r.manual_review_required
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["policy_name"] == "QOS-IN"
    assert rule["direction"] == "inbound"
    assert rule["interface"] == "GigabitEthernet0/0/1"
    assert len(rule["classes"]) == 1
    cls = rule["classes"][0]
    assert cls["classifier"] == "VOICE"
    assert cls["behavior"] == "VOICE-BEH"
    assert len(cls["matches"]) == 2
    assert any(m["type"] == "acl" and m["value"] == "3000" for m in cls["matches"])
    assert any(m["type"] == "dscp" and m["value"] == "ef" for m in cls["matches"])
    assert len(cls["actions"]) == 3


# ═══════════════════════════════════════════════════════════════════
# 2. Huawei missing classifier → warning
# ═══════════════════════════════════════════════════════════════════

def test_huawei_missing_classifier():
    config = """#
traffic behavior DATA
 car cir 20000
#
traffic policy QOS-OUT
 classifier MISSING behavior DATA
#
interface GigabitEthernet0/0/1
 traffic-policy QOS-OUT outbound
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    assert r.manual_review_required
    ctx = " ".join(r.missing_context)
    assert "MISSING" in ctx and "未定义" in ctx


# ═══════════════════════════════════════════════════════════════════
# 3. Huawei missing behavior → warning
# ═══════════════════════════════════════════════════════════════════

def test_huawei_missing_behavior():
    config = """#
traffic classifier WEB
 if-match dscp af21
#
traffic policy QOS-IN
 classifier WEB behavior MISSING_BEH
#
interface GigabitEthernet0/0/1
 traffic-policy QOS-IN inbound
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    ctx = " ".join(r.missing_context)
    assert "MISSING_BEH" in ctx


# ═══════════════════════════════════════════════════════════════════
# 4. H3C qos policy
# ═══════════════════════════════════════════════════════════════════

def test_h3c_qos():
    config = """#
traffic classifier H3C-TEST
 if-match acl 3001
#
traffic behavior H3C-BEH
 car cir 50000
 queue 5
#
traffic policy H3C-POL
 classifier H3C-TEST behavior H3C-BEH
#
interface GigabitEthernet1/0/1
 traffic-policy H3C-POL inbound
#"""
    r = a(config, "h3c")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert "H3C-TEST" in r.references.get("classifier", [])


# ═══════════════════════════════════════════════════════════════════
# 5. Cisco class-map + policy-map + service-policy complete
# ═══════════════════════════════════════════════════════════════════

def test_cisco_qos_full():
    config = """!
class-map match-all VOICE
 match access-group 100
 match dscp ef
!
policy-map QOS-IN
 class VOICE
  priority percent 30
  set dscp ef
 class class-default
  bandwidth remaining percent 70
!
interface GigabitEthernet0/1
 service-policy input QOS-IN
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert not r.manual_review_required
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["policy_name"] == "QOS-IN"
    assert rule["direction"] == "input"
    assert rule["interface"] == "GigabitEthernet0/1"
    assert len(rule["classes"]) == 2
    assert rule["classes"][0]["classifier"] == "VOICE"
    assert any(a["type"] == "priority" for a in rule["classes"][0]["actions"])


# ═══════════════════════════════════════════════════════════════════
# 6. Cisco missing class-map → fatal
# ═══════════════════════════════════════════════════════════════════

def test_cisco_missing_class_map():
    config = """!
policy-map TEST
 class NOT_DEFINED
  police 10000
!
interface GigabitEthernet0/1
 service-policy input TEST
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "fatal"
    ctx = " ".join(r.missing_context)
    assert "NOT_DEFINED" in ctx and "fatal" in ctx


# ═══════════════════════════════════════════════════════════════════
# 7. Cisco missing service-policy binding → warning
# ═══════════════════════════════════════════════════════════════════

def test_cisco_unbound_policy():
    config = """!
class-map match-all WEB
 match protocol http
!
policy-map WEB-POL
 class WEB
  bandwidth 5000
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    ctx = " ".join(r.missing_context)
    assert "未绑定接口" in ctx or "service-policy" in ctx


# ═══════════════════════════════════════════════════════════════════
# 8. ACL reference in class-map → ref tracked
# ═══════════════════════════════════════════════════════════════════

def test_cisco_acl_ref_tracked():
    config = """!
access-list 100 permit udp any any range 16384 32767
!
class-map match-all VOICE
 match access-group 100
!
policy-map PMAP
 class VOICE
  priority 1000
!
interface GigabitEthernet0/1
 service-policy input PMAP
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert "100" in r.references.get("acl", [])


# ═══════════════════════════════════════════════════════════════════
# 9. Huawei multiple classes parsed
# ═══════════════════════════════════════════════════════════════════

def test_huawei_multiple_classes():
    config = """#
traffic classifier VOICE
 if-match acl 3000
#
traffic behavior VOICE-BEH
 priority 5
#
traffic classifier DATA
 if-match acl 3001
#
traffic behavior DATA-BEH
 car cir 50000
#
traffic policy QOS-IN
 classifier VOICE behavior VOICE-BEH precedence 5
 classifier DATA behavior DATA-BEH precedence 10
#
interface GigabitEthernet0/0/1
 traffic-policy QOS-IN inbound
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 1
    assert len(r.rules[0]["classes"]) == 2


# ═══════════════════════════════════════════════════════════════════
# 10. Non-QoS config → skipped
# ═══════════════════════════════════════════════════════════════════

def test_non_qos_skipped():
    r = a("interface GigabitEthernet0/0/1\n ip address 10.0.0.1 255.255.255.0\n", "huawei")
    assert r.status == "skipped"


# ═══════════════════════════════════════════════════════════════════
# 11. Unsupported vendor → skipped
# ═══════════════════════════════════════════════════════════════════

def test_unsupported_vendor_skipped():
    r = a("class-map VOICE\n match dscp ef\n", "ruijie")
    assert r.status == "skipped"
