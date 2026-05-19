"""Phase 5-A Step 25: RoutePolicyAnalyzer — tests."""
import pytest
from core.analyzers.route_policy import RoutePolicyAnalyzer

analyzer = RoutePolicyAnalyzer()


def analyze(config: str, vendor: str = "huawei", domain: str = "routing", platform: str = "vrp"):
    return analyzer.analyze(config, vendor, domain, platform)


# ═══════════════════════════════════════════════════════════════════
# POSITIVE: Huawei route-policy + ip-prefix complete
# ═══════════════════════════════════════════════════════════════════

def test_huawei_route_policy_full():
    config = """#
bgp 65001
 router-id 2.2.2.2
 peer 192.168.1.2 as-number 65002
 peer 192.168.1.2 route-policy FROM_EBGP import
#
route-policy FROM_EBGP permit node 10
 if-match ip-prefix IMPORT
 apply local-preference 200
#
ip ip-prefix IMPORT permit 10.0.0.0 8 greater-equal 16 less-equal 24"""
    r = analyze(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert not r.manual_review_required
    assert len(r.rules) == 1
    assert r.rules[0]["policy_name"] == "FROM_EBGP"
    assert r.rules[0]["action"] == "permit"
    assert r.rules[0]["matches"] == [{"type": "prefix_list", "name": "IMPORT"}]
    assert r.rules[0]["sets"] == [{"type": "local_preference", "value": "200"}]
    assert r.references["policy"] == ["FROM_EBGP"]
    assert r.references["prefix_list"] == ["IMPORT"]


# ═══════════════════════════════════════════════════════════════════
# POSITIVE: Huawei route-policy reference missing ip-prefix → warning
# ═══════════════════════════════════════════════════════════════════

def test_huawei_missing_ip_prefix():
    config = """#
route-policy FILTER permit node 10
 if-match ip-prefix NOT_DEFINED
 apply local-preference 100
#"""
    r = analyze(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    assert r.manual_review_required
    assert any("NOT_DEFINED" in m for m in r.missing_context)


# ═══════════════════════════════════════════════════════════════════
# POSITIVE: H3C route-policy + acl reference
# ═══════════════════════════════════════════════════════════════════

def test_h3c_route_policy_with_acl():
    config = """#
acl number 3000
 rule 5 permit ip source 10.0.0.0 0.0.0.255 destination any
#
route-policy ACL-TEST permit node 10
 if-match acl 3000
 apply cost 10
#"""
    r = analyze(config, "h3c")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 1
    assert r.rules[0]["policy_name"] == "ACL-TEST"
    assert r.rules[0]["matches"][0]["type"] == "acl"
    assert r.rules[0]["sets"] == [{"type": "cost", "value": "10"}]
    # ACL 3000 is defined in config, no missing context
    assert not any("ACL" in m for m in r.missing_context)


# ═══════════════════════════════════════════════════════════════════
# POSITIVE: Cisco route-map + prefix-list complete
# ═══════════════════════════════════════════════════════════════════

def test_cisco_route_map_full():
    config = """!
route-map FROM_EBGP permit 10
 match ip address prefix-list IMPORT
 set local-preference 200
!
ip prefix-list IMPORT seq 5 permit 10.0.0.0/8 ge 16 le 24
!
router bgp 65001
 neighbor 192.168.1.2 remote-as 65002
 neighbor 192.168.1.2 route-map FROM_EBGP in
!"""
    r = analyze(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert not r.manual_review_required
    assert len(r.rules) == 1
    assert r.rules[0]["policy_name"] == "FROM_EBGP"
    assert r.rules[0]["matches"] == [{"type": "prefix_list", "name": "IMPORT"}]
    assert r.rules[0]["sets"] == [{"type": "local_preference", "value": "200"}]
    assert "IMPORT" in r.references["prefix_list"]


# ═══════════════════════════════════════════════════════════════════
# POSITIVE: Cisco route-map missing prefix-list → warning
# ═══════════════════════════════════════════════════════════════════

def test_cisco_missing_prefix_list():
    config = """!
route-map FROM_EBGP permit 10
 match ip address prefix-list MISSING
 set metric 20
!"""
    r = analyze(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    assert r.manual_review_required
    assert any("MISSING" in m for m in r.missing_context)


# ═══════════════════════════════════════════════════════════════════
# POSITIVE: BGP neighbor route-map in/out external reference
# ═══════════════════════════════════════════════════════════════════

def test_cisco_bgp_neighbor_route_map_ref():
    config = """!
router bgp 65001
 neighbor 10.0.0.2 remote-as 65003
 neighbor 10.0.0.2 route-map FROM_EBGP in
 neighbor 10.0.0.2 route-map TO_EBGP out
 redistribute ospf 1 route-map OSPF_TO_BGP
!"""
    r = analyze(config, "cisco")
    assert r.status == "analyzed"
    # All three policies referenced but none defined → warning
    assert r.risk_level == "warning"
    assert r.manual_review_required
    ctx = " ".join(r.missing_context)
    assert "FROM_EBGP" in ctx
    assert "TO_EBGP" in ctx
    assert "OSPF_TO_BGP" in ctx
    # Check external refs captured
    ext = r.references.get("external_refs", {})
    assert "FROM_EBGP" in ext
    assert "TO_EBGP" in ext
    assert "OSPF_TO_BGP" in ext


# ═══════════════════════════════════════════════════════════════════
# POSITIVE: Huawei import-route route-policy extraction
# ═══════════════════════════════════════════════════════════════════

def test_huawei_import_route_ref():
    config = """#
ospf 1
 import-route bgp route-policy BGP_TO_OSPF
#
bgp 65001
 peer 10.0.0.2 as-number 65002
 peer 10.0.0.2 route-policy FROM_EBGP import
#"""
    r = analyze(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    ext = r.references.get("external_refs", {})
    assert "BGP_TO_OSPF" in ext
    assert "FROM_EBGP" in ext
    ctx = " ".join(r.missing_context)
    assert "BGP_TO_OSPF" in ctx
    assert "FROM_EBGP" in ctx
    assert "影响路由导入/导出路径" in ctx


# ═══════════════════════════════════════════════════════════════════
# NEGATIVE: non-route-policy config → skipped
# ═══════════════════════════════════════════════════════════════════

def test_non_route_policy_skipped():
    config = """#
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.0
#"""
    r = analyze(config, "huawei")
    assert r.status == "skipped"
    assert r.risk_level == "info"


# ═══════════════════════════════════════════════════════════════════
# NEGATIVE: Cisco pure ACL without route-map → skipped
# ═══════════════════════════════════════════════════════════════════

def test_cisco_non_route_map_skipped():
    config = """!
access-list 100 permit ip 10.0.0.0 0.0.0.255 any
!"""
    r = analyze(config, "cisco")
    assert r.status == "skipped"


# ═══════════════════════════════════════════════════════════════════
# POSITIVE: vendor not supported → skipped
# ═══════════════════════════════════════════════════════════════════

def test_unsupported_vendor_skipped():
    r = analyze("route-map RM permit 10", "ruijie")
    assert r.status == "skipped"


# ═══════════════════════════════════════════════════════════════════
# POSITIVE: multiple sequences in one route-policy
# ═══════════════════════════════════════════════════════════════════

def test_huawei_multiple_sequences():
    config = """#
route-policy MULTI permit node 10
 if-match ip-prefix PREF_IN
 apply local-preference 200
#
route-policy MULTI permit node 20
 if-match ip-prefix PREF_LOCAL
 apply local-preference 150
#
ip ip-prefix PREF_IN permit 10.0.0.0 8
ip ip-prefix PREF_LOCAL permit 172.16.0.0 12
#"""
    r = analyze(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 2
    assert r.rules[0]["sequence"] == "10"
    assert r.rules[1]["sequence"] == "20"
    assert r.rules[0]["policy_name"] == "MULTI"
