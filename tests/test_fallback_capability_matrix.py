# -*- coding: utf-8 -*-
"""Tests that verify the Fallback Capability Matrix is internally consistent.

These tests check structural properties of the matrix document,
not fragile full-text matching.
"""

import re
import pytest

DOC_PATH = "docs/FALLBACK_CAPABILITY_MATRIX.md"

PLATFORMS = (
    "cisco_ios_xe", "h3c_comware", "huawei_vrp", "huawei_usg",
    "ruijie_rgos", "hillstone_stoneos", "topsec_tos", "dptech_fw",
)
DOMAINS = ("SWITCH", "ROUTER", "FIREWALL")
MANAGEMENT_SECTIONS = ("hostname", "sysname", "ntp", "NTP", "logging", "LOGGING",
                        "snmp", "SNMP", "aaa", "AAA", "password", "PASSWORD")
ACL_SECTIONS = ("acl", "ACL", "traffic-filter", "traffic-policy", "QoS", "qos")
FIREWALL_SECTIONS = ("firewall", "FIREWALL", "security-zone", "security-policy",
                      "zone", "address", "service", "policy")
ROUTER_SECTIONS = ("static route", "ospf", "bgp", "vrf", "router")


def _read_matrix():
    with open(DOC_PATH, encoding="utf-8") as f:
        return f.read()


def test_matrix_contains_all_8_vendor_platforms():
    text = _read_matrix()
    for v in PLATFORMS:
        assert v in text, f"Platform {v!r} not found in matrix"


def test_matrix_contains_all_3_domains():
    text = _read_matrix()
    for d in DOMAINS:
        assert d in text, f"Domain {d!r} not found in matrix"


def test_matrix_corpus_path_is_sanitized():
    text = _read_matrix()
    assert "corpus/sanitized_samples/" in text, \
        "Matrix must reference corpus/sanitized_samples/ as the primary corpus path"
    bare = re.findall(r"corpus/samples/", text)
    for m in bare:
        idx = text.index(m)
        window = text[max(0, idx - 150):idx + len(m) + 150]
        assert "sanitized" in window.lower() or "gitignore" in window.lower() or "ignore" in window.lower(), \
            f"Bare corpus/samples/ at pos {idx} without sanitized/ignore context: ...{window[:80]}..."


def test_matrix_has_management_section():
    text = _read_matrix()
    found = sum(1 for kw in MANAGEMENT_SECTIONS if kw in text)
    assert found >= 4, \
        f"MANAGEMENT section appears incomplete (found {found} keywords, expected >= 4)"


def test_matrix_has_acl_section():
    text = _read_matrix()
    found = sum(1 for kw in ACL_SECTIONS if kw in text)
    assert found >= 3, \
        f"ACL/QoS section appears incomplete (found {found} keywords, expected >= 3)"


def test_matrix_has_firewall_section():
    text = _read_matrix()
    found = sum(1 for kw in FIREWALL_SECTIONS if kw in text)
    assert found >= 4, \
        f"FIREWALL section appears incomplete (found {found} keywords, expected >= 4)"


def test_matrix_has_router_section():
    text = _read_matrix()
    found = sum(1 for kw in ROUTER_SECTIONS if kw in text)
    assert found >= 3, \
        f"ROUTER section appears incomplete (found {found} keywords, expected >= 3)"


def test_matrix_aaa_always_manual_review_or_redacted():
    """Verify the matrix states that AAA/password commands are always MANUAL_REVIEW or redacted."""
    text = _read_matrix()
    lines = text.splitlines()
    aaa_block = "\n".join(l for l in lines if "aaa" in l.lower() or "AAA" in l)
    assert "MANUAL_REVIEW" in aaa_block, \
        "Matrix must state that AAA commands go to MANUAL_REVIEW"
    assert "<redacted>" in aaa_block or "redacted" in aaa_block.lower(), \
        "Matrix must mention redaction for credentials"


def test_matrix_no_implicit_any_for_firewall_policy():
    """Verify the matrix explicitly prohibits implicit 'any' for firewall policies."""
    text = _read_matrix()
    firewall_lines = "\n".join(
        l for l in text.splitlines() if "firewall" in l.lower() or "MANUAL_REVIEW" in l
    )
    assert "any" in firewall_lines.lower(), \
        "Matrix must address firewall policy field completeness / no-implicit-any"
    assert "source-address" in text, \
        "Matrix must mention source-address requirement for firewall policies"


def test_matrix_lists_test_files():
    """Verify the matrix references real test files."""
    text = _read_matrix()
    test_files = [
        "test_rule_translator_management.py",
        "test_rule_translator_acl_binding.py",
        "test_rule_translator_firewall.py",
        "test_rule_translator_switch_multivendor.py",
        "test_rule_translator_router_multivendor.py",
    ]
    for f in test_files:
        assert f in text, f"Matrix does not reference test file {f!r}"


def test_matrix_acknowledges_main_pipeline():
    """Verify the matrix disclaimer mentions the main Parser → IR → Renderer pipeline."""
    text = _read_matrix()
    assert "Parser" in text and "IR" in text, \
        "Matrix must mention the main translation pipeline (Parser → IR → Renderer)"
    assert "fallback" in text.lower(), \
        "Matrix must explain the role of fallback"


def test_matrix_does_not_claim_service_policy_to_traffic_filter_auto_translation():
    """Verify the matrix does NOT claim service-policy → traffic-filter is auto-translatable.

    service-policy (QoS) and traffic-filter (ACL) are different features.
    Cisco service-policy input/output → Huawei/H3C traffic-filter inbound/outbound acl
    is NOT a safe automatic translation (semantic mismatch).
    """
    text = _read_matrix()
    lines = text.splitlines()
    auto_translate_sections = []
    in_auto_section = False
    for i, line in enumerate(lines):
        if "### Auto-translate" in line or "Auto-translate:" in line:
            in_auto_section = True
        elif in_auto_section and (line.startswith("## ") or line.startswith("### MANUAL") or line.startswith("### Not")):
            in_auto_section = False
        elif in_auto_section:
            auto_translate_sections.append((i + 1, line))

    bad_lines = [(ln, ln_text) for ln, ln_text in auto_translate_sections
                 if "service-policy" in ln_text and "traffic-filter" in ln_text.lower()]
    assert not bad_lines, \
        f"Auto-translate section must not claim service-policy → traffic-filter auto translation: {bad_lines}"


def test_matrix_firewall_future_work_not_in_auto_translate():
    """Capabilities that are not implemented must NOT appear in the Auto-translate table.

    Implemented capabilities (Topsec→Huawei USG zone/address/policy, Hillstone→Topsec
    zone/address/policy) should appear in auto-translate.
    Unimplemented dangerous features (NAT/IPSec/VPN/URL/AV/time-range etc.) must NOT.
    """
    text = _read_matrix()
    lines = text.splitlines()
    auto_block = []
    in_auto = False
    for line in lines:
        if "### Auto-translate" in line or "Auto-translate:" in line:
            in_auto = True
        elif in_auto and (line.startswith("## ") or line.startswith("### MANUAL") or line.startswith("### Not")):
            in_auto = False
        elif in_auto:
            auto_block.append(line.lower())

    auto_text = "\n".join(auto_block)

    assert "topsec → huawei usg" in auto_text and "zone" in auto_text, \
        "Topsec→Huawei USG zone should be in auto-translate table"
    assert "hillstone → topsec" in auto_text and "zone" in auto_text, \
        "Hillstone→Topsec zone should be in auto-translate table"

    import re
    assert not re.search(r"(?<![a-z])nat(?![a-z])", auto_text), \
        "NAT should not appear in auto-translate table"
    assert not re.search(r"(?<![a-z])ipsec(?![a-z])", auto_text), \
        "IPSec should not appear in auto-translate table"
    assert not re.search(r"(?<![a-z])vpn\s+(tunnel|policy|profile)", auto_text), \
        "VPN tunnel/policy/profile should not appear in auto-translate table"


def test_matrix_no_trailing_whitespace():
    """Verify the matrix document has no trailing whitespace on any line."""
    text = _read_matrix()
    bad = []
    for i, line in enumerate(text.splitlines(), 1):
        if line != line.rstrip():
            bad.append(f"line {i}: {repr(line[-30:])}")
    assert not bad, f"Trailing whitespace found:\n{bad}"