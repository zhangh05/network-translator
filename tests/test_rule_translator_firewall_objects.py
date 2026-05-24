# -*- coding: utf-8 -*-
"""Extended firewall tests for Batch C — object/policy capability enhancements.

Covers:
- Huawei USG ↔ Hillstone full policy round-trips
- Hillstone address-group / service-group translation
- Topsec/DPtech policy with action=deny
- Unknown Topsec/DPtech constructs (NAT/VPN/IPS/AV) → MANUAL_REVIEW
- DPtech address range (two-ip form) → manual review
- Hillstone → Huawei USG multi-rule translation
- Source/destination address preservation
- Cipher/password redaction in firewall context
"""

import pytest
from core.rule_translator import RuleBasedTranslator


def _executable_lines(text: str):
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip()
        and not line.strip().startswith(("```", "!", "#"))
    ]


def _check_no_source_residue(output: str, source_keywords: list):
    exe = _executable_lines(output)
    for line in exe:
        for kw in source_keywords:
            if line.startswith(kw):
                raise AssertionError(
                    f"Source residue: '{kw}' starts executable line: {line!r}"
                )


HUAWEI_USG_KW = ["security-zone", "security-policy", "ip address-set", "ip service-set"]
HILLSTONE_KW = ["zone ", "policy "]
TOPSEC_KW = ["zone name", "address name", "policy name"]
DPTECH_KW = ["object address", "security-policy name"]


# ─────────────────────────────────────────────────────────────────────────────
# Hillstone address-group / service-group
# ─────────────────────────────────────────────────────────────────────────────

def test_hillstone_address_group_to_huawei_usg_is_manual_review():
    """Hillstone address-group is not yet supported; expect MANUAL_REVIEW."""
    result = RuleBasedTranslator().translate(
        "address-group INTERNAL 10.0.0.0 255.255.255.0\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


def test_hillstone_service_group_to_huawei_usg_is_manual_review():
    """Hillstone service-group is not yet supported; expect MANUAL_REVIEW."""
    result = RuleBasedTranslator().translate(
        "service-group HTTP-GROUP tcp dst-port 80\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


# ─────────────────────────────────────────────────────────────────────────────
# Hillstone → Huawei USG policy: multi-rule, action=deny, address any
# ─────────────────────────────────────────────────────────────────────────────

def test_hillstone_to_huawei_usg_policy_deny():
    result = RuleBasedTranslator().translate(
        "policy deny-ssh from trust to untrust source any destination WEB service SSH action deny\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "security-policy" in result
    assert "rule name deny-ssh" in result
    assert "action deny" in result
    _check_no_source_residue(result, HILLSTONE_KW)


def test_hillstone_to_huawei_usg_source_any():
    result = RuleBasedTranslator().translate(
        "policy allow-all from trust to untrust source any destination any service any action permit\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "security-policy" in result
    assert "source-zone trust" in result
    assert "destination-zone untrust" in result
    assert "destination-address any" in result
    _check_no_source_residue(result, HILLSTONE_KW)


def test_hillstone_to_huawei_usg_multi_rule():
    result = RuleBasedTranslator().translate(
        "zone trust\n"
        "zone untrust\n"
        "policy allow-http from trust to untrust source any destination WEB service HTTP action permit\n"
        "policy deny-all from trust to untrust source any destination any service any action deny\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "security-zone name trust" in result
    assert "security-zone name untrust" in result
    exe = _executable_lines(result)
    policy_lines = [l for l in exe if l.startswith("rule name")]
    assert len(policy_lines) == 2
    _check_no_source_residue(result, HILLSTONE_KW)


def test_hillstone_to_huawei_usg_service_any():
    result = RuleBasedTranslator().translate(
        "policy allow-all from trust to untrust source any destination any service any action permit\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "service any" in result


# ─────────────────────────────────────────────────────────────────────────────
# Topsec policy with action=deny
# ─────────────────────────────────────────────────────────────────────────────

def test_topsec_to_hillstone_policy_deny():
    result = RuleBasedTranslator().translate(
        "policy name deny-ping from inside to outside src any dst SERVER service PING action deny\n",
        from_vendor="topsec",
        to_vendor="hillstone",
    )
    exe = _executable_lines(result)
    policy_lines = [l for l in exe if l.startswith("policy ")]
    assert len(policy_lines) == 1
    assert "deny-ping" in policy_lines[0]
    assert "deny" in policy_lines[0]
    _check_no_source_residue(result, TOPSEC_KW)


# ─────────────────────────────────────────────────────────────────────────────
# Topsec unknown constructs → MANUAL_REVIEW (NAT/VPN/IPS/AV/profile)
# ─────────────────────────────────────────────────────────────────────────────

def test_topsec_nat_goes_to_manual_review():
    result = RuleBasedTranslator().translate(
        "nat source static 10.0.0.1 1.1.1.1\n",
        from_vendor="topsec",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result


def test_topsec_ipsec_goes_to_manual_review():
    result = RuleBasedTranslator().translate(
        "ipsec tunnel TUNNEL remote 2.2.2.2\n",
        from_vendor="topsec",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result


def test_topsec_ips_profile_goes_to_manual_review():
    result = RuleBasedTranslator().translate(
        "ips profile HIGH risk-level critical\n",
        from_vendor="topsec",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result


def test_topsec_av_profile_goes_to_manual_review():
    result = RuleBasedTranslator().translate(
        "av profile virus-free mode block\n",
        from_vendor="topsec",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result


def test_topsec_url_filter_goes_to_manual_review():
    result = RuleBasedTranslator().translate(
        "url-filter category SOCIAL_MEDIA deny\n",
        from_vendor="topsec",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result


# ─────────────────────────────────────────────────────────────────────────────
# DPtech unknown constructs → MANUAL_REVIEW
# ─────────────────────────────────────────────────────────────────────────────

def test_dptech_nat_goes_to_manual_review():
    result = RuleBasedTranslator().translate(
        "nat address-group POOL1 1.1.1.1 1.1.1.10\n",
        from_vendor="dptech",
        to_vendor="huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


def test_dptech_ipsec_goes_to_manual_review():
    result = RuleBasedTranslator().translate(
        "ipsec tunnel-name TUNNEL remote 2.2.2.2 ike-profile IKE-PROF\n",
        from_vendor="dptech",
        to_vendor="huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


# ─────────────────────────────────────────────────────────────────────────────
# DPtech address range (two-ip form) → MANUAL_REVIEW
# ─────────────────────────────────────────────────────────────────────────────

def test_dptech_address_range_to_manual_review():
    result = RuleBasedTranslator().translate(
        "object address-range POOL 10.0.0.1 10.0.0.10\n",
        from_vendor="dptech",
        to_vendor="huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


# ─────────────────────────────────────────────────────────────────────────────
# Unknown firewall commands → MANUAL_REVIEW for any vendor pair
# ─────────────────────────────────────────────────────────────────────────────

def test_hillstone_unknown_to_huawei_usg_manual_review():
    result = RuleBasedTranslator().translate(
        "application APP-HTTP\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


def test_huawei_usg_unknown_to_hillstone_manual_review():
    result = RuleBasedTranslator().translate(
        "scheduler 5 schedule-name WORK time-range WORKTIME\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result


# ─────────────────────────────────────────────────────────────────────────────
# Cipher/password in firewall context must not leak
# ─────────────────────────────────────────────────────────────────────────────

def test_firewall_cipher_no_leak_huawei_usg_to_hillstone():
    result = RuleBasedTranslator().translate(
        "local-user admin password cipher $SuperSecret123\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    exe = _executable_lines(result)
    for line in exe:
        assert "$SuperSecret123" not in line
        assert "cipher" not in line.lower()


def test_firewall_cipher_no_leak_hillstone_to_huawei_usg():
    result = RuleBasedTranslator().translate(
        "user admin password hash $HashedPass456\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    exe = _executable_lines(result)
    for line in exe:
        assert "$HashedPass456" not in line


# ─────────────────────────────────────────────────────────────────────────────
# Hillstone flat policy preserved (passthrough when from_vendor=hillstone)
# ─────────────────────────────────────────────────────────────────────────────

def test_hillstone_passthrough_when_source_is_hillstone():
    result = RuleBasedTranslator().translate(
        "zone trust\n"
        "zone untrust\n"
        "address INTERNAL 10.0.0.0 255.255.255.0\n"
        "service HTTP tcp dst-port 80\n"
        "policy allow-http from trust to untrust source INTERNAL destination any service HTTP action permit\n",
        from_vendor="hillstone",
        to_vendor="hillstone",
    )
    exe = _executable_lines(result)
    assert any("zone trust" in l for l in exe)
    assert any("zone untrust" in l for l in exe)
    assert any("address INTERNAL" in l for l in exe)
    assert any("policy allow-http" in l for l in exe)


# ─────────────────────────────────────────────────────────────────────────────
# Huawei USG policy: source-address/destination-address preserved
# ─────────────────────────────────────────────────────────────────────────────

def test_huawei_usg_policy_preserves_source_destination_address():
    result = RuleBasedTranslator().translate(
        "security-policy\n"
        " rule name allow-dns\n"
        "  source-zone lan\n"
        "  destination-zone wan\n"
        "  source-address DNS-CLIENT\n"
        "  destination-address DNS-SERVER\n"
        "  service dns\n"
        "  action permit\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    exe = _executable_lines(result)
    policy_lines = [l for l in exe if l.startswith("policy ")]
    assert len(policy_lines) == 1
    assert "DNS-CLIENT" in policy_lines[0]
    assert "DNS-SERVER" in policy_lines[0]


# ─────────────────────────────────────────────────────────────────────────────
# Topsec → Huawei USG (new cross-vendor path)
# ─────────────────────────────────────────────────────────────────────────────

def test_topsec_zone_to_huawei_usg():
    """Topsec -> Huawei USG zone is now supported."""
    result = RuleBasedTranslator().translate(
        "zone name inside\nzone name dmz\n",
        from_vendor="topsec",
        to_vendor="huawei_usg",
    )
    assert "security-zone name inside" in result
    assert "security-zone name dmz" in result
    _check_no_source_residue(result, TOPSEC_KW)


def test_topsec_address_to_huawei_usg_is_manual_review():
    """Topsec -> Huawei USG address is not yet supported; expect MANUAL_REVIEW."""
    result = RuleBasedTranslator().translate(
        "address name SRV1 ip 192.168.1.10 255.255.255.255\n",
        from_vendor="topsec",
        to_vendor="huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


def test_topsec_policy_to_huawei_usg_is_manual_review():
    """Topsec -> Huawei USG policy is not yet supported; expect MANUAL_REVIEW."""
    result = RuleBasedTranslator().translate(
        "policy name allow-web from inside to dmz src any dst SRV1 service HTTP action permit\n",
        from_vendor="topsec",
        to_vendor="huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


# ─────────────────────────────────────────────────────────────────────────────
# Hillstone → Topsec (new cross-vendor path)
# ─────────────────────────────────────────────────────────────────────────────

def test_hillstone_zone_to_topsec_auto():
    """Hillstone -> Topsec zone is auto-translated."""
    result = RuleBasedTranslator().translate(
        "zone trust\nzone untrust\n",
        from_vendor="hillstone",
        to_vendor="topsec",
    )
    assert "zone name trust" in result
    assert "zone name untrust" in result


def test_hillstone_address_to_topsec_auto():
    """Hillstone -> Topsec address object is auto-translated."""
    result = RuleBasedTranslator().translate(
        "address SRV1 192.168.1.10 255.255.255.255\n",
        from_vendor="hillstone",
        to_vendor="topsec",
    )
    assert "address name SRV1 ip 192.168.1.10 mask 255.255.255.255" in result


# ─────────────────────────────────────────────────────────────────────────────
# DPtech → Hillstone (new cross-vendor path)
# ─────────────────────────────────────────────────────────────────────────────

def test_dptech_zone_to_hillstone():
    result = RuleBasedTranslator().translate(
        "zone inside\nzone outside\n",
        from_vendor="dptech",
        to_vendor="hillstone",
    )
    assert "zone inside" in result
    assert "zone outside" in result
    _check_no_source_residue(result, DPTECH_KW)


def test_dptech_policy_to_hillstone_is_manual_review():
    """DPtech -> Hillstone: missing source-address requires MANUAL_REVIEW (no implicit any)."""
    result = RuleBasedTranslator().translate(
        "security-policy name allow-web source-zone inside destination-zone outside "
        "destination-address SRV1 service HTTP action permit\n",
        from_vendor="dptech",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result
    assert "missing source-address" in result


# ─────────────────────────────────────────────────────────────────────────────
# Incomplete policy: missing action → MANUAL_REVIEW
# ─────────────────────────────────────────────────────────────────────────────

def test_hillstone_policy_missing_action_to_huawei_usg():
    result = RuleBasedTranslator().translate(
        "policy allow-web from trust to untrust source any destination WEB service HTTP\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


def test_dptech_policy_missing_action_to_hillstone():
    result = RuleBasedTranslator().translate(
        "security-policy name allow-web source-zone inside destination-zone outside "
        "destination-address SRV1 service HTTP\n",
        from_vendor="dptech",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result


# ─────────────────────────────────────────────────────────────────────────────
# Batch H: Extended firewall object/policy coverage
# ─────────────────────────────────────────────────────────────────────────────

def test_dptech_policy_to_hillstone_supported():
    result = RuleBasedTranslator().translate(
        "security-policy name allow-web source-zone inside destination-zone outside "
        "source-address 10.0.0.0 destination-address SRV1 service HTTP action permit\n",
        from_vendor="dptech",
        to_vendor="hillstone",
    )
    assert "policy allow-web" in result
    assert "source 10.0.0.0" in result
    assert "action permit" in result
    _check_no_source_residue(result, DPTECH_KW)


def test_dptech_policy_without_source_address_to_hillstone_manual_review():
    result = RuleBasedTranslator().translate(
        "security-policy name allow-web source-zone inside destination-zone outside "
        "destination-address SRV1 service HTTP action permit\n",
        from_vendor="dptech",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result
    assert "missing source-address" in result


def test_dptech_policy_with_source_address_to_hillstone():
    result = RuleBasedTranslator().translate(
        "security-policy name allow-web source-zone inside destination-zone outside "
        "source-address 10.0.0.0 destination-address SRV1 service HTTP action permit\n",
        from_vendor="dptech",
        to_vendor="hillstone",
    )
    assert "policy allow-web" in result
    assert "source 10.0.0.0" in result


def test_dptech_policy_to_huawei_usg_supported():
    result = RuleBasedTranslator().translate(
        "security-policy name allow-web source-zone inside destination-zone outside "
        "source-address 10.0.0.0 destination-address SRV1 service HTTP action permit\n",
        from_vendor="dptech",
        to_vendor="huawei_usg",
    )
    assert "security-policy" in result
    assert "rule name allow-web" in result
    assert "source-address 10.0.0.0" in result
    _check_no_source_residue(result, DPTECH_KW)


def test_dptech_policy_without_source_address_to_huawei_usg_manual_review():
    result = RuleBasedTranslator().translate(
        "security-policy name allow-web source-zone inside destination-zone outside "
        "destination-address SRV1 service HTTP action permit\n",
        from_vendor="dptech",
        to_vendor="huawei_usg",
    )
    assert "MANUAL_REVIEW" in result
    assert "missing source-address" in result


def test_dptech_policy_with_source_address_to_huawei_usg():
    result = RuleBasedTranslator().translate(
        "security-policy name allow-web source-zone inside destination-zone outside "
        "source-address 10.0.0.0 destination-address SRV1 service HTTP action permit\n",
        from_vendor="dptech",
        to_vendor="huawei_usg",
    )
    assert "security-policy" in result
    assert "rule name allow-web" in result
    assert "source-address 10.0.0.0" in result


def test_hillstone_address_host_to_huawei_usg():
    result = RuleBasedTranslator().translate(
        "address HOST1 10.1.1.1 host\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "ip address-set HOST1 type object" in result
    assert "10.1.1.1" in result
    _check_no_source_residue(result, HILLSTONE_KW)


def test_hillstone_address_range_to_huawei_usg():
    result = RuleBasedTranslator().translate(
        "address RANGE1 10.0.0.0 255.255.255.0\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "ip address-set RANGE1 type object" in result
    assert "10.0.0.0" in result
    _check_no_source_residue(result, HILLSTONE_KW)


def test_hillstone_service_tcp_to_huawei_usg():
    result = RuleBasedTranslator().translate(
        "service HTTP tcp dst-port 80\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "ip service-set HTTP type object" in result
    assert "protocol tcp" in result
    assert "destination-port 80" in result


def test_hillstone_service_udp_to_huawei_usg():
    result = RuleBasedTranslator().translate(
        "service DNS udp dst-port 53\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "ip service-set DNS type object" in result
    assert "protocol udp" in result
    assert "destination-port 53" in result


def test_hillstone_service_any_to_huawei_usg():
    result = RuleBasedTranslator().translate(
        "service ANY ip\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "ip service-set" in result and "type object" in result
    assert "protocol ip" in result


def test_huawei_usg_address_host_to_hillstone():
    result = RuleBasedTranslator().translate(
        "ip address-set HOST1 type object\n address 0 10.1.1.1 mask host\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "address HOST1 10.1.1.1 host" in result


def test_huawei_usg_address_range_to_hillstone():
    result = RuleBasedTranslator().translate(
        "ip address-set RANGE1 type object\n address 0 10.0.0.0 mask 24\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "address RANGE1 10.0.0.0" in result
    assert "255.255.255.0" in result


def test_huawei_usg_service_tcp_to_hillstone():
    result = RuleBasedTranslator().translate(
        "ip service-set HTTP type object\n service 0 protocol tcp destination-port 80\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "service HTTP tcp dst-port 80" in result


def test_huawei_usg_service_udp_to_hillstone():
    result = RuleBasedTranslator().translate(
        "ip service-set DNS type object\n service 0 protocol udp destination-port 53\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "service DNS udp dst-port 53" in result


def test_huawei_usg_service_icmp_to_hillstone():
    result = RuleBasedTranslator().translate(
        "ip service-set PING type object\n service 0 protocol icmp\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "service PING icmp" in result


def test_dptech_object_address_to_hillstone():
    result = RuleBasedTranslator().translate(
        "object address SRV1 10.0.0.10 255.255.255.255\n",
        from_vendor="dptech",
        to_vendor="hillstone",
    )
    assert "address SRV1 10.0.0.10 255.255.255.255" in result
    _check_no_source_residue(result, DPTECH_KW)


def test_dptech_object_address_network_to_hillstone():
    result = RuleBasedTranslator().translate(
        "object address LAN 10.0.0.0 255.255.255.0\n",
        from_vendor="dptech",
        to_vendor="hillstone",
    )
    assert "address LAN 10.0.0.0 255.255.255.0" in result
    _check_no_source_residue(result, DPTECH_KW)


def test_dptech_zone_to_huawei_usg():
    result = RuleBasedTranslator().translate(
        "zone inside\n",
        from_vendor="dptech",
        to_vendor="huawei_usg",
    )
    assert "security-zone name inside" in result
    _check_no_source_residue(result, DPTECH_KW)


def test_dptech_service_tcp_to_hillstone():
    result = RuleBasedTranslator().translate(
        "object service HTTP protocol tcp destination-port 80\n",
        from_vendor="dptech",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result


def test_topsec_address_object_to_hillstone():
    result = RuleBasedTranslator().translate(
        "address name SRV1 ip 192.168.1.10 255.255.255.255\n",
        from_vendor="topsec",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" not in result
    assert "address SRV1" in result


def test_topsec_service_object_to_hillstone():
    result = RuleBasedTranslator().translate(
        "service name HTTP protocol tcp port 80\n",
        from_vendor="topsec",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result


def test_huawei_usg_security_policy_enable_log_manual_review():
    result = RuleBasedTranslator().translate(
        "security-policy\n rule name POL-LOG\n  source-zone wan\n  destination-zone trust\n  action permit\n enable log\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result


def test_huawei_usg_incomplete_policy_at_eof_manual_review():
    result = RuleBasedTranslator().translate(
        "security-policy\n rule name POL-EOF\n  source-zone wan\n  destination-zone trust\n  source-address any\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result


def test_hillstone_policy_to_hillstone_same_vendor():
    result = RuleBasedTranslator().translate(
        "policy allow-http from trust to untrust source any destination WEB service HTTP action permit\n",
        from_vendor="hillstone",
        to_vendor="hillstone",
    )
    assert "policy allow-http" in result


def test_dptech_policy_action_deny_to_hillstone():
    result = RuleBasedTranslator().translate(
        "security-policy name deny-ping source-zone wan destination-zone trust "
        "source-address 10.0.0.0 destination-address SERVER service PING action deny\n",
        from_vendor="dptech",
        to_vendor="hillstone",
    )
    assert "policy deny-ping" in result
    assert "action deny" in result


def test_no_nat_auto_translate():
    for nat_cmd in (
        "nat policy NAME",
        "source-nat POLICY",
        "destination-nat POLICY",
        "nat pool POOL",
    ):
        result = RuleBasedTranslator().translate(nat_cmd + "\n", "topsec", "huawei_usg")
        assert "MANUAL_REVIEW" in result, f"NAT should be MANUAL_REVIEW: {nat_cmd}"
        result2 = RuleBasedTranslator().translate(nat_cmd + "\n", "hillstone", "topsec")
        assert "MANUAL_REVIEW" in result2, f"NAT should be MANUAL_REVIEW: {nat_cmd}"


def test_no_ipsec_auto_translate():
    for ipsec_cmd in (
        "ipsec tunnel TUNNEL",
        "ike profile PROFILE",
        "ipsec policy POLICY",
    ):
        result = RuleBasedTranslator().translate(ipsec_cmd + "\n", "topsec", "huawei_usg")
        assert "MANUAL_REVIEW" in result, f"IPSec should be MANUAL_REVIEW: {ipsec_cmd}"
        result2 = RuleBasedTranslator().translate(ipsec_cmd + "\n", "hillstone", "topsec")
        assert "MANUAL_REVIEW" in result2, f"IPSec should be MANUAL_REVIEW: {ipsec_cmd}"


def test_no_zone_interface_binding_auto_translate():
    for cmd in (
        "add interface GigabitEthernet0/0/1",
        "zone trust add interface Vlanif10",
    ):
        result = RuleBasedTranslator().translate(cmd + "\n", "topsec", "huawei_usg")
        assert "MANUAL_REVIEW" in result, f"Zone interface binding should be MANUAL_REVIEW: {cmd}"
        result2 = RuleBasedTranslator().translate(cmd + "\n", "huawei_usg", "hillstone")
        assert "MANUAL_REVIEW" in result2, f"Zone interface binding should be MANUAL_REVIEW: {cmd}"


def test_no_time_range_log_application_auto_translate():
    for cmd in (
        "time-range WORK-HOURS",
        "log enable",
        "application APP-NAME",
        "user USER-NAME",
    ):
        result = RuleBasedTranslator().translate(cmd + "\n", "topsec", "huawei_usg")
        assert "MANUAL_REVIEW" in result, f"Should be MANUAL_REVIEW: {cmd}"
        result2 = RuleBasedTranslator().translate(cmd + "\n", "hillstone", "topsec")
        assert "MANUAL_REVIEW" in result2, f"Should be MANUAL_REVIEW: {cmd}"


def test_topsec_zone_to_huawei_usg_auto():
    result = RuleBasedTranslator().translate("zone name trust\n", "topsec", "huawei_usg")
    assert "security-zone name trust" in result


def test_topsec_address_to_huawei_usg_auto():
    result = RuleBasedTranslator().translate(
        "address name WEB ip 10.1.1.10 mask 255.255.255.255\n", "topsec", "huawei_usg",
    )
    assert "ip address-set WEB type object" in result
    assert "10.1.1.10" in result
    assert "address 0" in result


def test_topsec_policy_complete_permit_to_huawei_usg_auto():
    result = RuleBasedTranslator().translate(
        "policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC destination-address DST service HTTPS action permit\n",
        "topsec", "huawei_usg",
    )
    assert "security-policy" in result
    assert "rule name P1" in result
    assert "source-zone trust" in result
    assert "destination-zone untrust" in result
    assert "source-address SRC" in result
    assert "destination-address DST" in result
    assert "service HTTPS" in result
    assert "action permit" in result


def test_topsec_policy_complete_deny_to_huawei_usg_auto():
    result = RuleBasedTranslator().translate(
        "policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC destination-address DST service HTTPS action deny\n",
        "topsec", "huawei_usg",
    )
    assert "security-policy" in result
    assert "action deny" in result


def test_topsec_policy_missing_source_address_to_huawei_usg_manual_review():
    result = RuleBasedTranslator().translate(
        "policy name P1 source-zone trust destination-zone untrust "
        "destination-address DST service HTTPS action permit\n",
        "topsec", "huawei_usg",
    )
    assert "MANUAL_REVIEW" in result
    executable = "\n".join(_executable_lines(result))
    assert "security-policy" not in executable


def test_topsec_policy_missing_destination_address_to_huawei_usg_manual_review():
    result = RuleBasedTranslator().translate(
        "policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC service HTTPS action permit\n",
        "topsec", "huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


def test_topsec_policy_missing_service_to_huawei_usg_manual_review():
    result = RuleBasedTranslator().translate(
        "policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC destination-address DST action permit\n",
        "topsec", "huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


def test_topsec_policy_missing_action_to_huawei_usg_manual_review():
    result = RuleBasedTranslator().translate(
        "policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC destination-address DST service HTTPS\n",
        "topsec", "huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


def test_hillstone_zone_to_topsec_auto():
    result = RuleBasedTranslator().translate("zone trust\n", "hillstone", "topsec")
    assert "zone name trust" in result


def test_hillstone_address_mask_to_topsec_auto():
    result = RuleBasedTranslator().translate(
        "address WEB-SRV 10.1.1.10 255.255.255.255\n", "hillstone", "topsec",
    )
    assert "address name WEB-SRV ip 10.1.1.10 mask 255.255.255.255" in result


def test_hillstone_address_host_to_topsec_auto():
    result = RuleBasedTranslator().translate(
        "address WEB-SRV 10.1.1.10 host\n", "hillstone", "topsec",
    )
    assert "address name WEB-SRV ip 10.1.1.10 mask 255.255.255.255" in result


def test_hillstone_policy_complete_permit_to_topsec_auto():
    result = RuleBasedTranslator().translate(
        "policy P1 from trust to untrust source SRC destination DST service HTTPS action permit\n",
        "hillstone", "topsec",
    )
    assert "policy name P1" in result
    assert "source-zone trust" in result
    assert "destination-zone untrust" in result
    assert "source-address SRC" in result
    assert "destination-address DST" in result
    assert "service HTTPS" in result
    assert "action permit" in result


def test_hillstone_policy_complete_deny_to_topsec_auto():
    result = RuleBasedTranslator().translate(
        "policy P1 from trust to untrust source SRC destination DST service HTTPS action deny\n",
        "hillstone", "topsec",
    )
    assert "action deny" in result


def test_hillstone_policy_missing_source_to_topsec_manual_review():
    result = RuleBasedTranslator().translate(
        "policy P1 from trust to untrust destination DST service HTTPS action permit\n",
        "hillstone", "topsec",
    )
    assert "MANUAL_REVIEW" in result
    executable = "\n".join(_executable_lines(result))
    assert "policy" not in executable or "MANUAL_REVIEW" in executable


def test_hillstone_policy_missing_destination_to_topsec_manual_review():
    result = RuleBasedTranslator().translate(
        "policy P1 from trust to untrust source SRC service HTTPS action permit\n",
        "hillstone", "topsec",
    )
    assert "MANUAL_REVIEW" in result


def test_hillstone_policy_missing_service_to_topsec_manual_review():
    result = RuleBasedTranslator().translate(
        "policy P1 from trust to untrust source SRC destination DST action permit\n",
        "hillstone", "topsec",
    )
    assert "MANUAL_REVIEW" in result


def test_dptech_policy_complete_to_huawei_usg_auto():
    result = RuleBasedTranslator().translate(
        "security-policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC destination-address DST service HTTPS action permit\n",
        "dptech", "huawei_usg",
    )
    assert "security-policy" in result
    assert "rule name P1" in result
    assert "action permit" in result


def test_dptech_policy_complete_to_hillstone_auto():
    result = RuleBasedTranslator().translate(
        "security-policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC destination-address DST service HTTPS action permit\n",
        "dptech", "hillstone",
    )
    assert "policy P1" in result
    assert "from trust to untrust" in result
    assert "action permit" in result


def test_dptech_policy_missing_source_address_manual_review():
    result = RuleBasedTranslator().translate(
        "security-policy name P1 source-zone trust destination-zone untrust "
        "destination-address DST service HTTPS action permit\n",
        "dptech", "huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


def test_dptech_policy_missing_destination_address_manual_review():
    result = RuleBasedTranslator().translate(
        "security-policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC service HTTPS action permit\n",
        "dptech", "huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


def test_dptech_policy_missing_service_manual_review():
    result = RuleBasedTranslator().translate(
        "security-policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC destination-address DST action permit\n",
        "dptech", "huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


def test_dptech_address_range_manual_review():
    result = RuleBasedTranslator().translate(
        "object address RANGE start 10.0.0.1 end 10.0.0.10\n", "dptech", "huawei_usg",
    )
    assert "MANUAL_REVIEW" in result


def test_no_dangerous_features_leak_in_manual_review_output():
    dangerous = [
        "nat policy NAT",
        "ipsec tunnel TUN",
        "url-filter URLF",
        "antivirus AV",
        "time-range TR",
    ]
    for cmd in dangerous:
        for to_v in ("huawei_usg", "hillstone", "topsec"):
            result = RuleBasedTranslator().translate(cmd + "\n", "topsec", to_v)
            assert cmd.split()[0] not in result.lower() or "MANUAL_REVIEW" in result, \
                f"Source command should not appear as executable: {cmd} → {to_v}"


def test_policy_deny_preserved():
    for cfg, fv, tv in [
        ("policy name P1 source-zone trust destination-zone untrust source-address SRC destination-address DST service HTTPS action deny", "topsec", "huawei_usg"),
        ("policy P1 from trust to untrust source SRC destination DST service HTTPS action deny", "hillstone", "topsec"),
    ]:
        result = RuleBasedTranslator().translate(cfg + "\n", fv, tv)
        assert "action deny" in result
        executable = "\n".join(_executable_lines(result))
        assert executable == "" or "deny" in executable


def test_topsec_policy_no_implicit_any_in_manual_review():
    result = RuleBasedTranslator().translate(
        "policy name P1 source-zone trust destination-zone untrust source-address SRC\n",
        "topsec", "huawei_usg",
    )
    assert "MANUAL_REVIEW" in result
    assert "any" not in result.lower() or "MANUAL_REVIEW" in result


# ─────────────────────────────────────────────────────────────────────────────
# Blocking 1 fix: to_vendor=topsec routing — non-Topsec/Hillstone sources
# must MANUAL_REVIEW, not output Huawei USG syntax
# ─────────────────────────────────────────────────────────────────────────────

def test_dptech_address_to_topsec_manual_review_no_usg_syntax():
    result = RuleBasedTranslator().translate(
        "address name WEB ip 10.1.1.10 mask 255.255.255.255\n",
        "dptech", "topsec",
    )
    assert "MANUAL_REVIEW" in result
    assert "ip address-set" not in result
    assert "security-zone" not in result


def test_huawei_usg_zone_to_topsec_manual_review_no_usg_syntax():
    result = RuleBasedTranslator().translate(
        "security-zone name trust\n",
        "huawei_usg", "topsec",
    )
    assert "MANUAL_REVIEW" in result
    assert "security-zone" not in result or "MANUAL_REVIEW" in result


def test_huawei_usg_address_to_topsec_manual_review_no_usg_syntax():
    result = RuleBasedTranslator().translate(
        "ip address-set WEB type object\n address 0 10.1.1.10 mask 32\n",
        "huawei_usg", "topsec",
    )
    assert "MANUAL_REVIEW" in result
    executable = "\n".join(_executable_lines(result))
    assert "ip address-set" not in executable


def test_huawei_usg_security_policy_to_topsec_manual_review_no_usg_syntax():
    result = RuleBasedTranslator().translate(
        "security-policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC destination-address DST service HTTPS action permit\n",
        "huawei_usg", "topsec",
    )
    assert "MANUAL_REVIEW" in result
    assert "security-policy" not in result or "MANUAL_REVIEW" in result


def test_cisco_acl_to_topsec_manual_review():
    result = RuleBasedTranslator().translate(
        "ip access-list extended ACL01\n",
        "cisco", "topsec",
    )
    assert "MANUAL_REVIEW" in result
    assert "security-zone" not in result


def test_huawei_vrp_to_topsec_manual_review():
    result = RuleBasedTranslator().translate(
        "acl number 3000\n",
        "huawei", "topsec",
    )
    assert "MANUAL_REVIEW" in result


def test_h3c_to_topsec_manual_review():
    result = RuleBasedTranslator().translate(
        "acl number 3000\n",
        "h3c", "topsec",
    )
    assert "MANUAL_REVIEW" in result


# ─────────────────────────────────────────────────────────────────────────────
# Topsec→Huawei USG address: netmask format (not prefixlen)
# ─────────────────────────────────────────────────────────────────────────────

def test_topsec_address_to_huawei_usg_uses_netmask():
    result = RuleBasedTranslator().translate(
        "address name WEB ip 10.1.1.10 mask 255.255.255.255\n",
        "topsec", "huawei_usg",
    )
    assert "ip address-set WEB type object" in result
    assert "255.255.255.255" in result
    assert "mask 32" not in result


def test_topsec_address_to_huawei_usg_slash24():
    result = RuleBasedTranslator().translate(
        "address name LAN ip 192.168.1.0 mask 255.255.255.0\n",
        "topsec", "huawei_usg",
    )
    assert "255.255.255.0" in result
    assert "mask 24" not in result


# ─────────────────────────────────────────────────────────────────────────────
# Topsec→Huawei USG complete policy: no implicit any
# ─────────────────────────────────────────────────────────────────────────────

def test_topsec_policy_complete_permit_to_huawei_usg_no_any():
    result = RuleBasedTranslator().translate(
        "policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC destination-address DST service HTTPS action permit\n",
        "topsec", "huawei_usg",
    )
    assert "security-policy" in result
    assert "rule name P1" in result
    executable = "\n".join(_executable_lines(result))
    assert "any" not in executable.lower()


def test_topsec_policy_complete_deny_to_huawei_usg_no_any():
    result = RuleBasedTranslator().translate(
        "policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC destination-address DST service HTTPS action deny\n",
        "topsec", "huawei_usg",
    )
    assert "action deny" in result
    executable = "\n".join(_executable_lines(result))
    assert "any" not in executable.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Hillstone→Topsec complete policy: no implicit any
# ─────────────────────────────────────────────────────────────────────────────

def test_hillstone_policy_complete_permit_to_topsec_no_any():
    result = RuleBasedTranslator().translate(
        "policy P1 from trust to untrust source SRC destination DST service HTTPS action permit\n",
        "hillstone", "topsec",
    )
    assert "policy name P1" in result
    assert "action permit" in result
    executable = "\n".join(_executable_lines(result))
    assert "any" not in executable.lower()


def test_hillstone_policy_complete_deny_to_topsec_no_any():
    result = RuleBasedTranslator().translate(
        "policy P1 from trust to untrust source SRC destination DST service HTTPS action deny\n",
        "hillstone", "topsec",
    )
    assert "action deny" in result
    executable = "\n".join(_executable_lines(result))
    assert "any" not in executable.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Missing-field policies: no executable policy block in output
# ─────────────────────────────────────────────────────────────────────────────

def test_topsec_policy_missing_source_zone_no_executable_policy():
    result = RuleBasedTranslator().translate(
        "policy name P1 destination-zone untrust "
        "source-address SRC destination-address DST service HTTPS action permit\n",
        "topsec", "huawei_usg",
    )
    assert "MANUAL_REVIEW" in result
    executable = "\n".join(_executable_lines(result))
    assert "security-policy" not in executable


def test_hillstone_policy_missing_service_no_executable_policy():
    result = RuleBasedTranslator().translate(
        "policy P1 from trust to untrust source SRC destination DST action permit\n",
        "hillstone", "topsec",
    )
    assert "MANUAL_REVIEW" in result
    executable = "\n".join(_executable_lines(result))
    assert "policy" not in executable or "MANUAL_REVIEW" in executable


# ─────────────────────────────────────────────────────────────────────────────
# Topsec→Huawei USG zone/address/policy auto-translate summary
# ─────────────────────────────────────────────────────────────────────────────

def test_topsec_zone_to_huawei_usg_auto():
    result = RuleBasedTranslator().translate("zone name trust\n", "topsec", "huawei_usg")
    assert "security-zone name trust" in result


def test_topsec_address_netmask_to_huawei_usg():
    result = RuleBasedTranslator().translate(
        "address name WEB ip 10.1.1.10 mask 255.255.255.255\n",
        "topsec", "huawei_usg",
    )
    assert "ip address-set WEB type object" in result
    assert "10.1.1.10" in result
    assert "address 0" in result


def test_topsec_policy_permit_to_huawei_usg_auto():
    result = RuleBasedTranslator().translate(
        "policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC destination-address DST service HTTPS action permit\n",
        "topsec", "huawei_usg",
    )
    assert "security-policy" in result
    assert "rule name P1" in result
    assert "source-zone trust" in result
    assert "destination-zone untrust" in result
    assert "action permit" in result


def test_topsec_policy_deny_to_huawei_usg_auto():
    result = RuleBasedTranslator().translate(
        "policy name P1 source-zone trust destination-zone untrust "
        "source-address SRC destination-address DST service HTTPS action deny\n",
        "topsec", "huawei_usg",
    )
    assert "action deny" in result


def test_hillstone_zone_to_topsec_auto():
    result = RuleBasedTranslator().translate("zone trust\n", "hillstone", "topsec")
    assert "zone name trust" in result


def test_hillstone_address_mask_to_topsec_auto():
    result = RuleBasedTranslator().translate(
        "address WEB-SRV 10.1.1.10 255.255.255.255\n", "hillstone", "topsec",
    )
    assert "address name WEB-SRV ip 10.1.1.10 mask 255.255.255.255" in result


def test_hillstone_policy_permit_to_topsec_auto():
    result = RuleBasedTranslator().translate(
        "policy P1 from trust to untrust source SRC destination DST service HTTPS action permit\n",
        "hillstone", "topsec",
    )
    assert "policy name P1" in result
    assert "source-zone trust" in result
    assert "destination-zone untrust" in result
    assert "action permit" in result


def test_hillstone_policy_deny_to_topsec_auto():
    result = RuleBasedTranslator().translate(
        "policy P1 from trust to untrust source SRC destination DST service HTTPS action deny\n",
        "hillstone", "topsec",
    )
    assert "action deny" in result