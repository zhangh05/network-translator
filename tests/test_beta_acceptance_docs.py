# -*- coding: utf-8 -*-
"""Tests for Beta acceptance documentation consistency.

Verifies that docs/BETA_ACCEPTANCE_2026-05-25.md and
docs/beta_acceptance_2026_05_25.json have matching data, and that
neither document contains over-claiming statements.
"""

import json
import re
import pytest

JSON_PATH = "docs/beta_acceptance_2026_05_25.json"
MD_PATH = "docs/BETA_ACCEPTANCE_2026-05-25.md"


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def json_data():
    with open(JSON_PATH, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def md_text():
    with open(MD_PATH, encoding="utf-8") as f:
        return f.read()


# ── JSON structure ──────────────────────────────────────────────────────────


class TestJsonParsable:
    def test_json_is_valid(self, json_data):
        assert isinstance(json_data, dict)

    def test_beta_ready(self, json_data):
        assert json_data["beta_ready"] == "YES_CONDITIONAL"

    def test_date(self, json_data):
        assert json_data["date"] == "2026-05-25"

    def test_domains_contain_switch(self, json_data):
        assert "SWITCH" in json_data["domains"]

    def test_domains_contain_router(self, json_data):
        assert "ROUTER" in json_data["domains"]

    def test_domains_contain_firewall(self, json_data):
        assert "FIREWALL" in json_data["domains"]

    def test_vendor_platforms_count(self, json_data):
        assert len(json_data["vendor_platforms"]) == 8

    def test_vendor_platforms_include_cisco(self, json_data):
        assert "cisco_ios_xe" in json_data["vendor_platforms"]

    def test_vendor_platforms_include_h3c(self, json_data):
        assert "h3c_comware" in json_data["vendor_platforms"]

    def test_vendor_platforms_include_huawei_vrp(self, json_data):
        assert "huawei_vrp" in json_data["vendor_platforms"]

    def test_vendor_platforms_include_huawei_usg(self, json_data):
        assert "huawei_usg" in json_data["vendor_platforms"]

    def test_vendor_platforms_include_ruijie(self, json_data):
        assert "ruijie_rgos" in json_data["vendor_platforms"]

    def test_vendor_platforms_include_hillstone(self, json_data):
        assert "hillstone_stoneos" in json_data["vendor_platforms"]

    def test_vendor_platforms_include_topsec(self, json_data):
        assert "topsec_tos" in json_data["vendor_platforms"]

    def test_vendor_platforms_include_dptech(self, json_data):
        assert "dptech_fw" in json_data["vendor_platforms"]


# ── Test numbers match ──────────────────────────────────────────────────────


class TestNumbersMatchJson:
    def test_known_tolerated_failures(self, json_data):
        assert json_data["tests"]["ci_gate"]["known_tolerated_failures"] == 0

    def test_output_redaction_passed(self, json_data):
        assert json_data["tests"]["output_redaction"]["passed"] == 47

    def test_ci_gate_passed(self, json_data):
        assert json_data["tests"]["ci_gate"]["passed"] == 2345

    def test_project_store_related_passed(self, json_data):
        assert json_data["tests"]["project_store_related"]["passed"] == 124

    def test_redaction_patterns(self, json_data):
        assert json_data["redaction"]["patterns"] == 14

    def test_redaction_function_name(self, json_data):
        assert json_data["redaction"]["function"] == "redact_sensitive_output()"

    def test_redaction_covered_paths(self, json_data):
        assert len(json_data["redaction"]["covered_paths"]) == 5
        for p in ["translate_project_new", "translate_project_reuse",
                  "get_project_detail", "list_projects", "update_project_store"]:
            assert p in json_data["redaction"]["covered_paths"]

    def test_next_actions_p0_count(self, json_data):
        assert len(json_data["next_actions"][0]["items"]) == 2  # GH Actions + real device; tolerated failures resolved


# ── Markdown structure ──────────────────────────────────────────────────────


class TestMdContainsExpectedSections:
    def test_beta_ready_conditional(self, md_text):
        assert "BETA_READY = YES (conditional)" in md_text

    def test_project_positioning(self, md_text):
        assert "可审计、可验证、可复核" in md_text
        assert '不是"AI 配置翻译网页"' in md_text

    def test_no_overclaim(self, md_text):
        overclaims = [
            "complete production ready",
            "fully automatic migration",
            "完整支持所有交换配置",
            "完整路由协议迁移",
            "完整防火墙迁移",
        ]
        for phrase in overclaims:
            assert phrase not in md_text, f"Overclaim found: {phrase!r}"

    def test_no_plaintext_secrets(self, md_text):
        secrets = ["SECRET_KEY", "PUBLIC_COMM", "RADIUS_KEY"]
        for s in secrets:
            assert s not in md_text, f"Secret leaked into doc: {s!r}"

    def test_known_limits_section_exists(self, md_text):
        assert "## 7. 已知限制" in md_text or "## 7. Known Limitations" in md_text

    def test_github_actions_mentioned(self, md_text):
        assert "GitHub Actions" in md_text

    def test_tolerated_failures_mentioned(self, md_text, json_data):
        expected = str(json_data["tests"]["ci_gate"]["known_tolerated_failures"])
        assert expected in md_text and ("known" in md_text.lower() or "tolerated" in md_text.lower())

    def test_core_chain_described(self, md_text):
        assert "Parser → IR → Renderer → Validator" in md_text

    def test_strongest_chain_h3c_cisco(self, md_text):
        assert "H3C" in md_text or "Comware" in md_text

    def test_fallback_described_as_complement(self, md_text):
        assert "不等同于完整" in md_text or "不是完整语义" in md_text

    def test_ui_features_listed(self, md_text):
        features = ["翻译结果 tab", "复制全部配置", "复制可部署配置", "复制风险报告"]
        for f in features:
            assert f in md_text, f"UI feature missing: {f!r}"

    def test_redaction_covered(self, md_text):
        assert "redact_sensitive_output()" in md_text or "14 种" in md_text

    def test_live_device_validation_required(self, md_text):
        assert "真实设备" in md_text or "仿真环境" in md_text


# ── Cross-doc number consistency ────────────────────────────────────────────


class TestCrossDocConsistency:
    """Spot-check that key numbers in JSON match MD."""

    KP: list[tuple[str, str]] = [
        ("47 passed", "47"),
        ("14 种", None),
    ]

    def test_ci_gate_number_in_md(self, md_text, json_data):
        expected = str(json_data["tests"]["ci_gate"]["passed"])
        assert expected in md_text, f"CI gate number {expected} not found in MD"

    def test_known_tolerated_in_md(self, md_text, json_data):
        expected = str(json_data["tests"]["ci_gate"]["known_tolerated_failures"])
        assert expected in md_text, f"Known tolerated {expected} not found in MD"

    def test_output_redaction_number_in_md(self, md_text, json_data):
        expected = str(json_data["tests"]["output_redaction"]["passed"])
        assert expected in md_text, f"Output redaction test count {expected} not found in MD"


# ── Specific paths described ────────────────────────────────────────────────


class TestPathsCovered:
    def test_llm_success_path_covered(self, json_data):
        assert json_data["redaction"]["llm_success_path_covered"] is True

    def test_fallback_path_covered(self, json_data):
        assert json_data["redaction"]["fallback_path_covered"] is True

    def test_disk_persistence_clean(self, json_data):
        assert json_data["redaction"]["disk_persistence_clean"] is True


# ── Known failures detail ───────────────────────────────────────────────────


class TestKnownFailuresDetail:
    def test_known_failure_count_matches(self, json_data):
        assert len(json_data["known_failures"]) == 0  # all resolved

    def test_each_failure_has_reason(self, json_data):
        for f in json_data["known_failures"]:
            assert "test" in f and "reason" in f
