"""Phase 5-A Step 26: IpsecAnalyzer — tests."""
import pytest
from core.analyzers.ipsec import IpsecAnalyzer

analyzer = IpsecAnalyzer()


def a(config: str, vendor: str = "huawei", domain: str = "routing", platform: str = "vrp"):
    return analyzer.analyze(config, vendor, domain, platform)


# ═══════════════════════════════════════════════════════════════════
# 1. Huawei complete ipsec policy
# ═══════════════════════════════════════════════════════════════════

def test_huawei_ipsec_full():
    config = """#
ike proposal 10
 encryption-algorithm aes-256
 authentication-algorithm sha256
 dh group14
 sa duration 86400
#
ike peer VPN-PEER
 pre-shared-key SimpleStr@123
 remote-address 203.0.113.1
 ike-proposal 10
 local-address 10.0.0.1
 local-id 10.0.0.1
#
ipsec proposal TRANS
 esp authentication-algorithm sha256
 esp encryption-algorithm aes-256
#
ipsec policy VPN 1 isakmp
 security acl 3000
 ike-peer VPN-PEER
 proposal TRANS
 remote-address 203.0.113.1
 pfs group14
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert not r.manual_review_required
    assert len(r.rules) == 1
    assert r.rules[0]["policy_name"] == "VPN seq 1"
    assert r.rules[0]["ike_peer"] == "VPN-PEER"
    assert r.rules[0]["ipsec_proposal"] == "TRANS"
    assert r.rules[0]["security_acl"] == "3000"


# ═══════════════════════════════════════════════════════════════════
# 2. Huawei missing ACL → warning
# ═══════════════════════════════════════════════════════════════════

def test_huawei_missing_acl():
    config = """#
ike proposal 10
 encryption-algorithm aes-256
 authentication-algorithm sha256
#
ike peer P1
 pre-shared-key SimpleStr@123
 remote-address 10.0.0.2
#
ipsec proposal T1
 esp authentication-algorithm sha256
 esp encryption-algorithm aes-192
#
ipsec policy POL 1 isakmp
 ike-peer P1
 proposal T1
 remote-address 10.0.0.2
"""
    r = a(config, "huawei")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    assert r.manual_review_required
    ctx = " ".join(r.missing_context)
    assert "security acl" in ctx and "fatal" in ctx


# ═══════════════════════════════════════════════════════════════════
# 3. H3C ike/ipsec proposal + policy
# ═══════════════════════════════════════════════════════════════════

def test_h3c_ipsec():
    config = """#
ike proposal 1
 encryption-algorithm aes-cbc-128
 authentication-algorithm md5
 dh group2
#
ipsec proposal PROP-A
 esp authentication-algorithm sha1
 esp encryption-algorithm aes-cbc-128
#
ipsec policy MAP 1 isakmp
 security acl 3001
 ike-peer H3C-PEER
 proposal PROP-A
 remote-address 192.168.1.1
#
ike peer H3C-PEER
 pre-shared-key Test@321
 remote-address 192.168.1.1
 ike-proposal 1
"""
    r = a(config, "h3c")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 1
    assert r.rules[0]["security_acl"] == "3001"


# ═══════════════════════════════════════════════════════════════════
# 4. Cisco crypto map complete
# ═══════════════════════════════════════════════════════════════════

def test_cisco_crypto_map_full():
    config = """!
crypto isakmp policy 10
 encryption aes 256
 hash sha256
 authentication pre-share
 group 14
 lifetime 86400
!
crypto isakmp key MyKey123 address 203.0.113.1
!
crypto ipsec transform-set TS1 esp-aes 256 esp-sha256-hmac
!
crypto map CMAP 10 ipsec-isakmp
 match address 100
 set peer 203.0.113.1
 set transform-set TS1
 set pfs group14
!
access-list 100 permit ip 10.0.0.0 0.0.0.255 192.168.0.0 0.0.255.255
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert not r.manual_review_required
    assert len(r.rules) == 1
    assert r.rules[0]["policy_name"] == "CMAP seq 10"
    assert r.rules[0]["match_address"] == "100"
    assert r.rules[0]["set_peer"] == ["203.0.113.1"]
    assert r.rules[0]["transform_set"] == "TS1"


# ═══════════════════════════════════════════════════════════════════
# 5. Cisco missing transform-set → fatal
# ═══════════════════════════════════════════════════════════════════

def test_cisco_missing_transform_set():
    config = """!
crypto map CMAP 10 ipsec-isakmp
 match address 100
 set peer 10.0.0.1
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "fatal"
    assert r.manual_review_required
    ctx = " ".join(r.missing_context)
    assert "transform-set" in ctx and "fatal" in ctx


# ═══════════════════════════════════════════════════════════════════
# 6. Cisco missing match address → fatal
# ═══════════════════════════════════════════════════════════════════

def test_cisco_missing_match_address():
    config = """!
crypto ipsec transform-set TS1 esp-aes esp-sha-hmac
!
crypto map CMAP 10 ipsec-isakmp
 set peer 10.0.0.1
 set transform-set TS1
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "fatal"
    ctx = " ".join(r.missing_context)
    assert "match address" in ctx and "fatal" in ctx


# ═══════════════════════════════════════════════════════════════════
# 7. Cisco crypto profile
# ═══════════════════════════════════════════════════════════════════

def test_cisco_crypto_profile():
    config = """!
crypto ipsec transform-set T1 esp-aes esp-sha-hmac
!
crypto ipsec profile PROFILE1
 set transform-set T1
 match address 101
!"""
    r = a(config, "cisco")
    assert r.status == "analyzed"
    assert r.risk_level == "info"
    assert len(r.rules) == 0  # profiles are checked for refs but don't become rules
    # Check transform-set ref is captured
    assert "T1" in r.references.get("transform_set", [])


# ═══════════════════════════════════════════════════════════════════
# 8. ASA tunnel-group identification
# ═══════════════════════════════════════════════════════════════════

def test_asa_tunnel_group():
    config = """!
crypto ikev1 policy 10
 authentication pre-share
 encryption aes-256
 hash sha
 group 2
 lifetime 86400
!
crypto ikev1 key MyKey123 address 0.0.0.0 0.0.0.0
!
tunnel-group 203.0.113.1 type ipsec-l2l
tunnel-group 203.0.113.1 ipsec-attributes
 ikev1 pre-shared-key Secr3tKey
!"""
    r = a(config, "asa")
    assert r.status == "analyzed"
    assert not r.risk_level == "fatal"  # PSK present, info/warning
    assert len(r.rules) == 1
    assert r.rules[0]["type"] == "tunnel_group"
    assert r.rules[0]["pre_shared_key"] != "missing"


# ═══════════════════════════════════════════════════════════════════
# 9. ASA tunnel-group missing PSK → warning
# ═══════════════════════════════════════════════════════════════════

def test_asa_missing_psk():
    config = """!
tunnel-group 10.0.0.1 type ipsec-l2l
tunnel-group 10.0.0.1 ipsec-attributes
!"""
    r = a(config, "asa")
    assert r.status == "analyzed"
    assert r.risk_level == "warning"
    ctx = " ".join(r.missing_context)
    assert "pre-shared-key" in ctx


# ═══════════════════════════════════════════════════════════════════
# 10. Non-IPsec config → skipped
# ═══════════════════════════════════════════════════════════════════

def test_non_ipsec_skipped():
    config = """#
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.0
#"""
    r = a(config, "huawei")
    assert r.status == "skipped"


# ═══════════════════════════════════════════════════════════════════
# 11. Unsupported vendor → skipped
# ═══════════════════════════════════════════════════════════════════

def test_unsupported_vendor_skipped():
    r = a("ike proposal 1\n", "ruijie")
    assert r.status == "skipped"
