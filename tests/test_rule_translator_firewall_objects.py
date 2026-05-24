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

def test_hillstone_zone_to_topsec_is_manual_review():
    """Hillstone -> Topsec zone is not yet supported; expect MANUAL_REVIEW."""
    result = RuleBasedTranslator().translate(
        "zone trust\nzone untrust\n",
        from_vendor="hillstone",
        to_vendor="topsec",
    )
    assert "MANUAL_REVIEW" in result


def test_hillstone_address_to_topsec_is_manual_review():
    """Hillstone -> Topsec address object is not yet supported; expect MANUAL_REVIEW."""
    result = RuleBasedTranslator().translate(
        "address SRV1 192.168.1.10 255.255.255.255\n",
        from_vendor="hillstone",
        to_vendor="topsec",
    )
    assert "MANUAL_REVIEW" in result


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