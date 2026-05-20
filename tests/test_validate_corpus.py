"""Tests for corpus validation (data governance checks)."""

import json
from pathlib import Path

from tools.validate_corpus import (
    _is_acceptable_ip,
    _check_no_real_ips,
    _check_forbidden_patterns,
    _check_hostname_leak,
    _validate_annotation_schema,
    run_validation,
    _is_known_subfeature,
)


def test_acceptable_ips():
    assert _is_acceptable_ip("10.0.0.1") is True
    assert _is_acceptable_ip("172.16.0.1") is True
    assert _is_acceptable_ip("192.168.1.1") is True
    assert _is_acceptable_ip("198.18.0.1") is True
    assert _is_acceptable_ip("198.19.255.255") is True
    assert _is_acceptable_ip("192.0.2.100") is True
    assert _is_acceptable_ip("198.51.100.50") is True
    assert _is_acceptable_ip("203.0.113.1") is True
    assert _is_acceptable_ip("255.255.255.0") is True


def test_acceptable_ips_rejects_public():
    # These are potential public IPs
    assert _is_acceptable_ip("8.8.8.8") is False


def test_check_no_real_ips():
    content = "ip address 10.0.0.1 255.255.255.0\nip address 8.8.8.8 255.255.255.0\n"
    findings = _check_no_real_ips(content, "test.txt")
    assert len(findings) >= 1
    assert any(f["value"] == "8.8.8.8" for f in findings)
    assert not any(f["value"] == "10.0.0.1" for f in findings)
    assert not any(f["value"] == "255.255.255.0" for f in findings)


def test_check_no_real_ips_clean():
    content = "ip address 10.0.0.1 255.255.255.0\n"
    findings = _check_no_real_ips(content, "test.txt")
    assert len(findings) == 0


def test_check_forbidden_patterns_finds_password():
    content = "username admin password hunter2\n"
    findings = _check_forbidden_patterns(content, "test.txt")
    assert len(findings) >= 1
    assert findings[0]["type"] == "forbidden_pattern"


def test_check_forbidden_patterns_clean():
    content = "hostname CoreRouter\nsnmp-server community __REDACTED__ ro\n"
    findings = _check_forbidden_patterns(content, "test.txt")
    assert len(findings) == 0

def test_check_forbidden_redacted_allows_redacted_values():
    content = "username admin password __REDACTED__\nisakmp key __REDACTED__\npre-shared-key __REDACTED__\n"
    findings = _check_forbidden_patterns(content, "test.txt")
    assert len(findings) == 0

def test_check_forbidden_snmp_community():
    content = "snmp-server community public ro\n"
    findings = _check_forbidden_patterns(content, "test.txt")
    assert len(findings) >= 1

def test_check_forbidden_isakmp_key():
    content = "crypto isakmp key mysecret address 0.0.0.0\n"
    findings = _check_forbidden_patterns(content, "test.txt")
    assert len(findings) >= 1

def test_check_forbidden_preshared_key():
    content = "  pre-shared-key MySecretKey123\n"
    findings = _check_forbidden_patterns(content, "test.txt")
    assert len(findings) >= 1

def test_check_forbidden_auth_key():
    content = "authentication key Sup3rS3cr3t\n"
    findings = _check_forbidden_patterns(content, "test.txt")
    assert len(findings) >= 1

def test_check_forbidden_certificate():
    content = "certificate private-key BEGIN RSA PRIVATE KEY\n"
    findings = _check_forbidden_patterns(content, "test.txt")
    assert len(findings) >= 1


def test_check_hostname_leak_finds_real():
    content = "ip host corp-dc1.example.com 10.0.0.1\n"
    findings = _check_hostname_leak(content, "test.txt")
    assert len(findings) >= 1
    assert findings[0]["type"] == "potential_real_hostname"


def test_check_hostname_leak_clean():
    content = "hostname Router1\nip domain-name lab.local\n"
    findings = _check_hostname_leak(content, "test.txt")
    assert len(findings) == 0


def test_validate_annotation_schema_valid():
    ann = {
        "id": "test-001",
        "classification": {"vendor": "cisco", "domain": "routing", "features": ["ospf"]},
        "annotation": {
            "expected_translation": {"target_vendor": "huawei"},
            "verification": {"deployable": True, "manual_review_required": False},
        },
        "config": {},
        "source": {},
    }
    issues = _validate_annotation_schema(ann, "test.json")
    assert len(issues) == 0


def test_validate_annotation_schema_invalid_vendor():
    ann = {
        "id": "test-001",
        "classification": {"vendor": "oracle", "domain": "routing", "features": []},
        "annotation": {"expected_translation": {}, "verification": {}},
        "config": {},
        "source": {},
    }
    issues = _validate_annotation_schema(ann, "test.json")
    assert any(i["type"] == "invalid_vendor" for i in issues)


def test_validate_annotation_schema_invalid_domain():
    ann = {
        "id": "test-001",
        "classification": {"vendor": "cisco", "domain": "datacenter", "features": []},
        "annotation": {"expected_translation": {}, "verification": {}},
        "config": {},
        "source": {},
    }
    issues = _validate_annotation_schema(ann, "test.json")
    assert any(i["type"] == "invalid_domain" for i in issues)


def test_validate_annotation_schema_verification_types():
    ann = {
        "id": "test-001",
        "classification": {"vendor": "cisco", "domain": "routing", "features": []},
        "annotation": {"expected_translation": {}, "verification": {"deployable": "yes", "manual_review_required": 0}},
        "config": {},
        "source": {},
    }
    issues = _validate_annotation_schema(ann, "test.json")
    assert any(i["type"] == "schema_type_error" for i in issues)


def test_is_known_subfeature():
    assert _is_known_subfeature("nat_server") is True
    assert _is_known_subfeature("nat_source") is True
    assert _is_known_subfeature("nat") is False
    assert _is_known_subfeature("ospf") is False


def test_run_validation_full():
    """Run full validation on the actual corpus — should pass."""
    result = run_validation()
    assert result["pass"] is True, f"Validation failed: {result['fatal']} fatal, {result['warning']} warning"
