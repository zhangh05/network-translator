"""Phase 5-B Step 28: ObjectAnalyzer — tests."""
import pytest
from core.analyzers.object import ObjectAnalyzer

analyzer = ObjectAnalyzer()


def a(config: str, vendor: str = "huawei", domain: str = "firewall", platform: str = "vrp"):
    return analyzer.analyze(config, vendor, domain, platform)


# ═══════════════════════════════════════════════════════════════════
# 1. Huawei address-set + address (full)
# ═══════════════════════════════════════════════════════════════════

def test_huawei_address_set():
    config = """#
 ip address-set LAN_NET
  address 10.0.0.0 255.255.255.0
  address 192.168.1.0 255.255.255.0
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["object_type"] == "address"
    assert rule["name"] == "LAN_NET"
    assert len(rule["members"]) == 2
    assert "10.0.0.0/255.255.255.0" in rule["members"]

# ═══════════════════════════════════════════════════════════════════
# 2. Huawei service-set + service
# ═══════════════════════════════════════════════════════════════════

def test_huawei_service_set():
    config = """#
 ip service-set WEB_SVC
  service tcp source-port 0 to 65535 destination-port 80
  service tcp source-port 0 to 65535 destination-port 443
#"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["object_type"] == "service"
    assert rule["name"] == "WEB_SVC"
    assert len(rule["services"]) == 2
    assert rule["services"][0]["protocol"] == "tcp"
    assert "destination-port 80" in rule["services"][0]["spec"]

# ═══════════════════════════════════════════════════════════════════
# 3. H3C address-set + service-set
# ═══════════════════════════════════════════════════════════════════

def test_h3c_mixed_objects():
    config = """#
 ip address-set TRUSTED
  address 10.0.0.0 255.0.0.0
#
 ip service-set SSH
  service tcp source-port 0 to 65535 destination-port 22
#"""
    r = a(config, "h3c")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 2
    addr = next(x for x in r.rules if x["name"] == "TRUSTED")
    svc = next(x for x in r.rules if x["name"] == "SSH")
    assert len(addr["members"]) == 1
    assert len(svc["services"]) == 1

# ═══════════════════════════════════════════════════════════════════
# 4. Cisco ASA object network host/subnet
# ═══════════════════════════════════════════════════════════════════

def test_asa_object_network():
    config = """!
object network LAN_NET
 subnet 10.0.0.0 255.255.255.0
object network HOST_1
 host 192.168.1.1
object network RANGE
 range 10.0.0.1 10.0.0.254
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 3
    lan = next(x for x in r.rules if x["name"] == "LAN_NET")
    host = next(x for x in r.rules if x["name"] == "HOST_1")
    rng = next(x for x in r.rules if x["name"] == "RANGE")
    assert "10.0.0.0/255.255.255.0" in lan["members"]
    assert "192.168.1.1/32" in host["members"]
    assert "10.0.0.1-10.0.0.254" in rng["members"]

# ═══════════════════════════════════════════════════════════════════
# 5. Cisco ASA object-group network
# ═══════════════════════════════════════════════════════════════════

def test_asa_object_group_network():
    config = """!
object-group network SERVERS
 network-object object LAN_NET
 network-object 10.1.0.0 255.255.0.0
 network-object host 10.2.0.1
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    assert r.manual_review_required
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["object_type"] == "network_group"
    assert rule["name"] == "SERVERS"
    assert len(rule["members"]) == 3
    assert "object:LAN_NET" in rule["members"]
    assert "10.1.0.0/255.255.0.0" in rule["members"]
    assert "10.2.0.1/32" in rule["members"]

# ═══════════════════════════════════════════════════════════════════
# 6. Cisco ASA object-group service
# ═══════════════════════════════════════════════════════════════════

def test_asa_object_group_service():
    config = """!
object-group service WEB_PORTS
 service-object tcp destination eq 80
 service-object tcp destination eq 443
 service-object object HTTP_SVC
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    assert r.manual_review_required
    assert len(r.rules) == 1
    rule = r.rules[0]
    assert rule["object_type"] == "service_group"
    assert len(rule["services"]) == 3

# ═══════════════════════════════════════════════════════════════════
# 7. Group 引用未定义对象 → warning
# ═══════════════════════════════════════════════════════════════════

def test_missing_object_ref():
    config = """!
object-group network OUTER
 network-object object INNER
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    assert r.manual_review_required
    ctx = " ".join(r.missing_context)
    assert "INNER" in ctx and "未定义" in ctx

# ═══════════════════════════════════════════════════════════════════
# 8. 非 object 配置 → skipped
# ═══════════════════════════════════════════════════════════════════

def test_non_object_skipped():
    r = a("interface GigabitEthernet0/0/1\n ip address 10.0.0.1 255.255.255.0\n", "huawei")
    assert r.status == "skipped"


# ═══════════════════════════════════════════════════════════════════
# 9. 不支持的 vendor → skipped
# ═══════════════════════════════════════════════════════════════════

def test_unsupported_vendor_skipped():
    r = a("address-set TEST\n  address 10.0.0.0 255.255.255.0\n", "ruijie")
    assert r.status == "skipped"


# ═══════════════════════════════════════════════════════════════════
# 10. Circuit ref: object-group → object-group circular
# ═══════════════════════════════════════════════════════════════════

def test_circular_object_group():
    config = """!
object-group network A
 network-object object B
!
object-group network B
 network-object object A
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "fatal"
    ctx = " ".join(r.missing_context)
    assert "循环引用" in ctx


# ═══════════════════════════════════════════════════════════════════
# P1-1: Registry resolves address_object/service_object → ObjectAnalyzer
# ═══════════════════════════════════════════════════════════════════

def test_registry_has_address_object_analyzer():
    from core.analyzers import AnalyzerRegistry
    reg = AnalyzerRegistry()
    assert reg.has_analyzer("address_object"), "address_object must have registered analyzer"

def test_registry_has_service_object_analyzer():
    from core.analyzers import AnalyzerRegistry
    reg = AnalyzerRegistry()
    assert reg.has_analyzer("service_object"), "service_object must have registered analyzer"

def test_registry_address_object_is_object_analyzer():
    from core.analyzers import AnalyzerRegistry
    reg = AnalyzerRegistry()
    cls_name = type(reg.get_analyzer("address_object")).__name__
    assert cls_name == "ObjectAnalyzer", f"Expected ObjectAnalyzer, got {cls_name}"

def test_registry_service_object_is_object_analyzer():
    from core.analyzers import AnalyzerRegistry
    reg = AnalyzerRegistry()
    cls_name = type(reg.get_analyzer("service_object")).__name__
    assert cls_name == "ObjectAnalyzer", f"Expected ObjectAnalyzer, got {cls_name}"

def test_registry_not_noop_for_address_object():
    from core.analyzers import AnalyzerRegistry, NoopAnalyzer
    reg = AnalyzerRegistry()
    analyzer = reg.get_analyzer("address_object")
    assert not isinstance(analyzer, NoopAnalyzer), "address_object must not be NoopAnalyzer"

def test_registry_not_noop_for_service_object():
    from core.analyzers import AnalyzerRegistry, NoopAnalyzer
    reg = AnalyzerRegistry()
    analyzer = reg.get_analyzer("service_object")
    assert not isinstance(analyzer, NoopAnalyzer), "service_object must not be NoopAnalyzer"

def test_registry_analyze_all_produces_analyzed_results():
    """FeatureAnalyzerNode-like run: ASA object-group config yields analyzed results, not Noop skipped."""
    from core.analyzers import AnalyzerRegistry
    reg = AnalyzerRegistry()
    config = """!
object-group network SERVERS
 network-object 10.1.0.0 255.255.0.0
!
object-group service WEB
 service-object tcp destination eq 80
!"""
    results = reg.analyze_all(config, "cisco", "firewall", "asa", ["address_object", "service_object"])
    assert len(results) == 2, f"expected 2 results, got {len(results)}"
    for r in results:
        assert r.status != "skipped", f"{r.feature} was skipped (Noop): {r.notes}"
        assert r.risk_level != "none"
    features = {r.feature for r in results}
    assert "address_object" in features, "address_object must produce analyzer results"
