# -*- coding: utf-8 -*-
"""Real-world sample residue regression tests.

Reads actual user configuration samples and verifies:
1. Source vendor executable residue count == 0 (for cross-vendor)
2. MANUAL_REVIEW items are properly categorized and non-empty
3. No sensitive information leakage (redaction verified)
4. Statistics are reported per-sample

Samples (read-only):
- /Users/zhangh01/Desktop/1.txt  — Huawei VRP V200R019C10SPC500 switch config
- /Users/zhangh01/Desktop/test_config.txt  — H3C Comware sample (optional)
"""

import os
import re
import pytest
from core.rule_translator import RuleBasedTranslator

SAMPLE_1_PATH = "/Users/zhangh01/Desktop/1.txt"
SAMPLE_2_PATH = "/Users/zhangh01/Desktop/test_config.txt"

HUAWEI_RESIDUE_KEYWORDS = []
H3C_RESIDUE_KEYWORDS = []
CISCO_RESIDUE_KEYWORDS = ["channel-group", "ip route "]
RUIJIE_RESIDUE_KEYWORDS = ["aggregateport", "port-group"]


def _read_sample(path: str) -> str:
    if not os.path.exists(path):
        pytest.skip(f"Sample file not found: {path}")
    with open(path, encoding="utf-8") as f:
        return f.read()


def _executable_lines(result: str) -> list:
    lines = []
    in_fence = False
    for raw in result.split("\n"):
        line = raw.strip()
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence or not line:
            continue
        if line.startswith("#") or line.startswith("!"):
            continue
        lines.append(line)
    return lines


def _count_manual_review(result: str) -> int:
    return result.count("MANUAL_REVIEW")


def _group_manual_review_categories(result: str) -> dict:
    categories = {}
    for line in result.split("\n"):
        if "MANUAL_REVIEW" in line:
            m = re.search(r"MANUAL_REVIEW\s+(?:unsupported source command:\s*)?(.+)", line)
            if m:
                reason = m.group(1).strip()
                if reason.startswith("traffic ") or reason.startswith("filter-policy") or reason.startswith("redirect"):
                    cat = "QoS/PBR"
                elif reason.startswith("stp ") or reason.startswith("instance") or reason.startswith("bpdu") or reason.startswith("root"):
                    cat = "STP"
                elif reason.startswith("vlan") or reason.startswith("batch"):
                    cat = "VLAN"
                elif reason.startswith("interface") and ("Vlanif" in reason or "Vlan-interface" in reason):
                    cat = "SVI"
                elif reason.startswith("bfd") or reason.startswith("nqa"):
                    cat = "BFD/NQA"
                elif reason.startswith("snmp") or reason.startswith("pki") or reason.startswith("ecc"):
                    cat = "Management"
                elif reason.startswith("authentication") or reason.startswith("dot1x") or reason.startswith("mac-access"):
                    cat = "AAA/802.1X"
                elif reason.startswith("acl") or reason.startswith("rule"):
                    cat = "ACL"
                elif reason.startswith("route-") or reason.startswith("ip route"):
                    cat = "Routing"
                elif reason.startswith("security") or reason.startswith("zone") or reason.startswith("address"):
                    cat = "Firewall"
                elif reason.startswith("portal") or reason.startswith("dns") or reason.startswith("clock"):
                    cat = "Services"
                else:
                    cat = "Other"
                categories[cat] = categories.get(cat, 0) + 1
    return categories


def _check_no_source_residue_cross_vendor(result: str, source_vendor: str, to_vendor: str):
    """Check that source-vendor-specific keywords don't leak into cross-vendor output."""
    if source_vendor == to_vendor:
        return
    same_family = source_vendor in ("huawei", "h3c") and to_vendor in ("huawei", "h3c")
    if same_family:
        return

    keywords = []
    if source_vendor == "huawei":
        keywords = ["undo "]
    elif source_vendor == "h3c":
        keywords = ["undo ", "bridge-aggregation"]
    elif source_vendor == "cisco":
        keywords = ["channel-group", "ip route "]
    elif source_vendor == "ruijie":
        keywords = ["aggregateport", "port-group"]

    exe = _executable_lines(result)
    for kw in keywords:
        nkw = kw.lower()
        for line in exe:
            assert nkw not in line.lower(), \
                f"[{source_vendor}→{to_vendor}] Source residue '{kw}' found: {line}"


def _check_no_sensitive_leak(result: str):
    """Check for obvious credential leaks (plaintext passwords, unredacted community strings)."""
    import re
    exe = _executable_lines(result)
    for line in exe:
        if "<redacted>" in line:
            continue
        if re.search(r"(?i)(?:password|secret)\s+(?:cipher\s+)?(?:\\|\$|0\s+\S{6,}|7\s+\S{6,})", line):
            pytest.fail(f"Sensitive data possibly leaked: {line}")


def _translate_and_analyze(text: str, from_v: str, to_v: str):
    t = RuleBasedTranslator()
    result = t.translate(text, from_v, to_v)
    exe = _executable_lines(result)
    mr_count = _count_manual_review(result)
    mr_cats = _group_manual_review_categories(result)
    return result, exe, mr_count, mr_cats


class TestRealWorldSample1Huawei:
    """Huawei VRP sample (1.txt) → multi-vendor residue checks."""

    @pytest.fixture(scope="class")
    def sample1_text(self):
        return _read_sample(SAMPLE_1_PATH)

    def test_huawei_to_cisco(self, sample1_text):
        result, exe, mr_count, mr_cats = _translate_and_analyze(sample1_text, "huawei", "cisco")
        _check_no_source_residue_cross_vendor(result, "huawei", "cisco")
        _check_no_sensitive_leak(result)
        assert mr_count > 0, "MANUAL_REVIEW should be emitted for complex features"
        top_cats = sorted(mr_cats.items(), key=lambda x: -x[1])[:5]
        print(f"\n  huawei→cisco: input={len(sample1_text.splitlines())} lines, "
              f"output={len(exe)}, mr={mr_count}, top={top_cats}")

    def test_huawei_to_h3c(self, sample1_text):
        result, exe, mr_count, mr_cats = _translate_and_analyze(sample1_text, "huawei", "h3c")
        _check_no_source_residue_cross_vendor(result, "huawei", "h3c")
        _check_no_sensitive_leak(result)
        assert mr_count > 0
        top_cats = sorted(mr_cats.items(), key=lambda x: -x[1])[:5]
        print(f"\n  huawei→h3c: input={len(sample1_text.splitlines())} lines, "
              f"output={len(exe)}, mr={mr_count}, top={top_cats}")

    def test_huawei_to_ruijie(self, sample1_text):
        result, exe, mr_count, mr_cats = _translate_and_analyze(sample1_text, "huawei", "ruijie")
        _check_no_source_residue_cross_vendor(result, "huawei", "ruijie")
        _check_no_sensitive_leak(result)
        assert mr_count > 0
        top_cats = sorted(mr_cats.items(), key=lambda x: -x[1])[:5]
        print(f"\n  huawei→ruijie: input={len(sample1_text.splitlines())} lines, "
              f"output={len(exe)}, mr={mr_count}, top={top_cats}")

    def test_huawei_to_huawei(self, sample1_text):
        result, exe, mr_count, mr_cats = _translate_and_analyze(sample1_text, "huawei", "huawei")
        _check_no_source_residue_cross_vendor(result, "huawei", "huawei")
        assert "sysname zjtzsh" in result
        print(f"\n  huawei→huawei: input={len(sample1_text.splitlines())} lines, "
              f"output={len(exe)}, mr={mr_count}")

    def test_huawei_to_hillstone(self, sample1_text):
        result, exe, mr_count, mr_cats = _translate_and_analyze(sample1_text, "huawei", "hillstone")
        _check_no_source_residue_cross_vendor(result, "huawei", "hillstone")
        _check_no_sensitive_leak(result)
        assert mr_count > 0
        top_cats = sorted(mr_cats.items(), key=lambda x: -x[1])[:5]
        print(f"\n  huawei→hillstone: input={len(sample1_text.splitlines())} lines, "
              f"output={len(exe)}, mr={mr_count}, top={top_cats}")

    def test_huawei_to_huawei_usg(self, sample1_text):
        result, exe, mr_count, mr_cats = _translate_and_analyze(sample1_text, "huawei", "huawei_usg")
        _check_no_source_residue_cross_vendor(result, "huawei", "huawei_usg")
        _check_no_sensitive_leak(result)
        assert mr_count > 0
        top_cats = sorted(mr_cats.items(), key=lambda x: -x[1])[:5]
        print(f"\n  huawei→huawei_usg: input={len(sample1_text.splitlines())} lines, "
              f"output={len(exe)}, mr={mr_count}, top={top_cats}")


class TestRealWorldSample2H3C:
    """H3C Comware sample — skip if file absent."""

    @pytest.fixture(scope="class")
    def sample2_text(self):
        return _read_sample(SAMPLE_2_PATH)

    def test_h3c_to_cisco(self, sample2_text):
        result, exe, mr_count, mr_cats = _translate_and_analyze(sample2_text, "h3c", "cisco")
        _check_no_source_residue_cross_vendor(result, "h3c", "cisco")
        _check_no_sensitive_leak(result)
        print(f"\n  h3c→cisco: input={len(sample2_text.splitlines())} lines, "
              f"output={len(exe)}, mr={mr_count}")

    def test_h3c_to_huawei(self, sample2_text):
        result, exe, mr_count, mr_cats = _translate_and_analyze(sample2_text, "h3c", "huawei")
        _check_no_source_residue_cross_vendor(result, "h3c", "huawei")
        _check_no_sensitive_leak(result)
        print(f"\n  h3c→huawei: input={len(sample2_text.splitlines())} lines, "
              f"output={len(exe)}, mr={mr_count}")