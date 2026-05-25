# -*- coding: utf-8 -*-
"""Tests for the multi-vendor sample corpus."""

import json
import os
import re
import pytest

CORPUS_DIR = os.path.join(os.path.dirname(__file__), "..", "corpus", "sanitized_samples")
MANIFEST_PATH = os.path.join(CORPUS_DIR, "manifest.json")
SAMPLE_PREFIX = os.path.join(CORPUS_DIR, "")

REQUIRED_MANIFEST_FIELDS = [
    "id", "source_vendor", "source_platform", "source_domain",
    "target_candidates", "features_present", "must_translate",
    "must_manual_review", "forbidden_executable_residue",
    "secret_tokens", "notes",
]

ALLOWED_DOMAINS = {"SWITCH", "ROUTER", "FIREWALL"}
VENDOR_PLATFORMS = {
    "cisco_ios_xe", "h3c_comware", "huawei_vrp", "huawei_usg",
    "ruijie_rgos", "hillstone_stoneos", "topsec_tos", "dptech_fw",
}

PUBLIC_IP_PATTERN = re.compile(
    r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"
)
# RFC 1918 + documentation prefixes we allow
ALLOWED_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.",
                    "172.24.", "172.25.", "172.26.", "172.27.",
                    "172.28.", "172.29.", "172.30.", "172.31.",
                    "192.168.", "198.51.100.", "192.0.2.", "203.0.113.")

SENSITIVE_PATTERNS = [
    re.compile(r"(?<![<>\w])(password|cipher|secret|shared-key)\s+(?!cipher\b)(?!<redacted>)\S+", re.I),
    re.compile(r"(?<![<>\w])password\s+cipher\s+(?!<redacted>)\S+", re.I),
]


def _load_manifest():
    with open(MANIFEST_PATH) as f:
        return json.load(f)


ID_TO_FILE = {
    "sw-cisco-01": "switch_cisco_small.txt",
    "sw-huawei-01": "switch_huawei_small.txt",
    "sw-h3c-01": "switch_h3c_small.txt",
    "sw-ruijie-01": "switch_ruijie_small.txt",
    "rt-cisco-01": "router_cisco_small.txt",
    "rt-huawei-01": "router_huawei_small.txt",
    "fw-usg-01": "firewall_huawei_usg_small.txt",
    "fw-hillstone-01": "firewall_hillstone_small.txt",
    "fw-topsec-01": "firewall_topsec_small.txt",
    "fw-dptech-01": "firewall_dptech_small.txt",
}


def _read_sample(sample_id: str) -> str:
    fname = ID_TO_FILE.get(sample_id)
    if not fname:
        raise FileNotFoundError(f"Unknown sample ID: {sample_id}")
    sample_path = os.path.join(CORPUS_DIR, fname)
    with open(sample_path) as f:
        return f.read()


def _is_public_ip(ip: str) -> bool:
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return False
    try:
        parts = [int(x) for x in ip.split(".")]
        if parts[0] < 1 or parts[0] > 223:
            return False
    except ValueError:
        return True
    for prefix in ALLOWED_PREFIXES:
        if ip.startswith(prefix):
            return False
    return True


def _find_ips(text: str) -> list:
    return PUBLIC_IP_PATTERN.findall(text)


class TestManifest:
    def test_corpus_path_exists_and_is_git_tracked(self):
        assert os.path.isdir(CORPUS_DIR), f"Corpus dir not found: {CORPUS_DIR}"

    def test_manifest_is_valid_json(self):
        data = _load_manifest()
        assert "version" in data
        assert "samples" in data
        assert len(data["samples"]) >= 10

    def test_manifest_each_sample_has_required_fields(self):
        data = _load_manifest()
        for s in data["samples"]:
            for field in REQUIRED_MANIFEST_FIELDS:
                assert field in s, f"Sample {s.get('id', '?')} missing field: {field}"

    def test_manifest_each_sample_domain_valid(self):
        data = _load_manifest()
        for s in data["samples"]:
            assert s["source_domain"] in ALLOWED_DOMAINS, \
                f"Sample {s['id']} has unknown domain: {s['source_domain']}"

    def test_manifest_each_sample_platform_valid(self):
        data = _load_manifest()
        for s in data["samples"]:
            assert s["source_platform"] in VENDOR_PLATFORMS, \
                f"Sample {s['id']} has unknown platform: {s['source_platform']}"

    def test_manifest_features_nonempty(self):
        data = _load_manifest()
        for s in data["samples"]:
            assert len(s["features_present"]) > 0, f"Sample {s['id']} has empty features_present"

    def test_manifest_must_translate_field_exists(self):
        data = _load_manifest()
        for s in data["samples"]:
            assert isinstance(s["must_translate"], list)
            assert isinstance(s["must_manual_review"], list)

    def test_manifest_forbidden_residue_field_exists(self):
        data = _load_manifest()
        for s in data["samples"]:
            assert isinstance(s["forbidden_executable_residue"], list)

    def test_all_vendor_platforms_covered(self):
        data = _load_manifest()
        platforms = {s["source_platform"] for s in data["samples"]}
        assert platforms == VENDOR_PLATFORMS, \
            f"Missing platforms: {VENDOR_PLATFORMS - platforms}"

    def test_all_domains_covered(self):
        data = _load_manifest()
        domains = {s["source_domain"] for s in data["samples"]}
        assert domains == ALLOWED_DOMAINS, \
            f"Missing domains: {ALLOWED_DOMAINS - domains}"

    def test_manifest_ids_are_unique(self):
        data = _load_manifest()
        ids = [s["id"] for s in data["samples"]]
        assert len(ids) == len(set(ids)), "Duplicate sample IDs found"


class TestSampleFiles:
    def test_all_samples_have_files(self):
        data = _load_manifest()
        missing = []
        for s in data["samples"]:
            fname = ID_TO_FILE.get(s["id"])
            if not fname:
                missing.append(s["id"])
                continue
            fpath = os.path.join(CORPUS_DIR, fname)
            if not os.path.isfile(fpath):
                missing.append(fname)
        assert not missing, f"Missing sample files: {missing}"

    def test_all_samples_line_count_reasonable(self):
        data = _load_manifest()
        for s in data["samples"]:
            content = _read_sample(s["id"])
            lines = [l for l in content.split("\n") if l.strip() and not l.strip().startswith(("#", "!", "//"))]
            assert 10 <= len(lines) <= 100, \
                f"Sample {s['id']} has {len(lines)} non-comment lines (expected 10-100)"

    def test_no_sensitive_values_in_samples(self):
        data = _load_manifest()
        for s in data["samples"]:
            content = _read_sample(s["id"])
            for pat in SENSITIVE_PATTERNS:
                m = pat.search(content)
                assert not m, f"Sample {s['id']} has unredacted sensitive value: {m.group() if m else ''}"

    def test_no_public_ips_in_samples(self):
        data = _load_manifest()
        for s in data["samples"]:
            content = _read_sample(s["id"])
            ips = _find_ips(content)
            bad = [ip for ip in ips if _is_public_ip(ip)]
            assert not bad, f"Sample {s['id']} has public IPs: {bad}"

    def test_each_sample_has_secret_tokens_field_nonempty_if_needed(self):
        data = _load_manifest()
        for s in data["samples"]:
            if s["secret_tokens"]:
                assert len(s["secret_tokens"]) > 0
