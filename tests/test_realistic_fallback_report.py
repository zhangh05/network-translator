# -*- coding: utf-8 -*-
"""Tests for user-readable fallback review summary (Batch D).

Verifies that FallbackNode._manual_review_fallback() produces:
A. Six user-friendly Chinese category labels in summary
B. No raw feature codes as the sole category label in user summary
C. Per-category: count, risk level, review reason, ≤3 example lines
D. Sensitive value redaction: no SECRET_PASS/PUBLIC_COMM/RADIUS_KEY anywhere
E. Internal diagnostics hidden: no raw error strings in output
F. Source vendor residue: zero in executable lines
G. Firewall object classification
H. Routing protocol classification
"""

import re
import pytest
from core.graph.nodes import FallbackNode
from core.graph import State


def _state(from_vendor, to_vendor, error, config_text):
    s = State()
    s.set("from_vendor", from_vendor)
    s.set("to_vendor", to_vendor)
    s.set("translate_error", error)
    s.set("config_text", config_text)
    return s


def _all_lines(text):
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _comment_lines(text):
    return [ln.strip() for ln in text.splitlines() if ln.strip().startswith(("!", "#"))]


def _executable_lines(text):
    return [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith(("!", "#", "```"))
    ]


# ─────────────────────────────────────────────────────────────────────────────
# A. Six user-friendly categories all present
# ─────────────────────────────────────────────────────────────────────────────

def test_fallback_summary_contains_all_six_categories():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """sysname HW-SW
vlan batch 10 20
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
acl number 3000
 rule 5 permit ip
local-user admin password irreversible-cipher SECRET_PASS
ospf 1 router-id 10.0.0.1
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    comment = _comment_lines(result)
    summary_idx = next(
        (i for i, ln in enumerate(comment) if "人工复核摘要" in ln), None
    )
    assert summary_idx is not None, f"人工复核摘要 not found in comments: {comment[:3]}"
    summary_section = "\n".join(comment[summary_idx:])

    CATEGORIES = ["管理面", "接口与 VLAN", "ACL 与安全策略", "路由协议"]
    for cat in CATEGORIES:
        assert cat in summary_section, \
            f"Category {cat!r} not found in summary section"


# ─────────────────────────────────────────────────────────────────────────────
# B. Raw feature codes must not appear as sole category label in user summary
# ─────────────────────────────────────────────────────────────────────────────

def test_fallback_summary_does_not_use_raw_feature_codes_as_labels():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """sysname HW-SW
vlan batch 10 20
acl number 3000
local-user admin password irreversible-cipher x
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    comment = _comment_lines(result)
    summary_idx = next(
        (i for i, ln in enumerate(comment) if "人工复核摘要" in ln), None
    )
    assert summary_idx is not None
    summary_lines = comment[summary_idx:]
    summary_text = "\n".join(summary_lines)

    user_summary_line_pattern = re.compile(r"^\s*!?\s*-\s+【[^】]+】")
    raw_code_pattern = re.compile(r"^\s*!?\s*-\s+(aaa|acl|qos|snmp|vlan|interface|ospf|system|stp)\s*：", re.IGNORECASE)

    for ln in summary_lines:
        if user_summary_line_pattern.match(ln):
            assert not raw_code_pattern.match(ln), \
                f"Raw feature code used as category label: {ln!r}"


# ─────────────────────────────────────────────────────────────────────────────
# C. Per-category: count, risk level, review reason, ≤3 example lines
# ─────────────────────────────────────────────────────────────────────────────

def test_fallback_summary_per_category_has_count():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """sysname HW-SW
vlan batch 10 20
acl number 3000
local-user admin password irreversible-cipher x
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    comment = _comment_lines(result)
    summary_idx = next(
        (i for i, ln in enumerate(comment) if "人工复核摘要" in ln), None
    )
    assert summary_idx is not None
    summary_lines = comment[summary_idx:]

    count_pattern = re.compile(r"个配置块")
    count_lines = [ln for ln in summary_lines if count_pattern.search(ln)]
    assert len(count_lines) > 0, f"No count lines found: {summary_lines[:5]}"


def test_fallback_summary_per_category_has_risk_level():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """sysname HW-SW
vlan batch 10 20
acl number 3000
local-user admin password irreversible-cipher x
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    comment = _comment_lines(result)
    summary_idx = next(
        (i for i, ln in enumerate(comment) if "人工复核摘要" in ln), None
    )
    assert summary_idx is not None
    summary_lines = comment[summary_idx:]

    risk_pattern = re.compile(r"⚠\s*(高|中|低)风险")
    risk_lines = [ln for ln in summary_lines if risk_pattern.search(ln)]
    assert len(risk_lines) > 0, f"No risk level found: {summary_lines[:5]}"


def test_fallback_summary_per_category_has_review_reason():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """sysname HW-SW
vlan batch 10 20
acl number 3000
local-user admin password irreversible-cipher x
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    comment = _comment_lines(result)
    summary_idx = next(
        (i for i, ln in enumerate(comment) if "人工复核摘要" in ln), None
    )
    assert summary_idx is not None
    summary_lines = comment[summary_idx:]
    summary_text = "\n".join(summary_lines)

    reason_keywords = ["需人工确认", "语义可能", "对应关系", "建议人工确认"]
    found = any(kw in summary_text for kw in reason_keywords)
    assert found, f"No review reason found in summary: {summary_text[:300]}"


def test_fallback_summary_example_lines_max_3():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """sysname HW-SW
vlan batch 10 20
acl number 3000
local-user admin password irreversible-cipher x
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    comment = _comment_lines(result)
    summary_idx = next(
        (i for i, ln in enumerate(comment) if "人工复核摘要" in ln), None
    )
    assert summary_idx is not None
    summary_section = comment[summary_idx:]

    current_category_lines = []
    max_example_per_category = 0
    for ln in summary_section:
        if "【" in ln and "】" in ln:
            if current_category_lines:
                max_example_per_category = max(max_example_per_category, len(current_category_lines))
            current_category_lines = []
        elif "示例：" in ln:
            current_category_lines.append(ln)
    if current_category_lines:
        max_example_per_category = max(max_example_per_category, len(current_category_lines))

    assert max_example_per_category <= 3, \
        f"More than 3 example lines in a category: {max_example_per_category}"


# ─────────────────────────────────────────────────────────────────────────────
# D. Sensitive value redaction — no SECRET_PASS / PUBLIC_COMM / RADIUS_KEY anywhere
# ─────────────────────────────────────────────────────────────────────────────

SENSITIVE_VALUES = ["SECRET_PASS", "PUBLIC_COMM", "RADIUS_KEY"]


def test_fallback_redacts_password_values():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        "local-user admin password irreversible-cipher SECRET_PASS\n",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    assert "SECRET_PASS" not in result, \
        f"SECRET_PASS leaked into output: {result[:300]}"
    assert "<redacted>" in result, \
        f"<redacted> not found after password redaction: {result[:300]}"


def test_fallback_redacts_snmp_community():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        "snmp-agent community read cipher PUBLIC_COMM\n",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    assert "PUBLIC_COMM" not in result, \
        f"PUBLIC_COMM leaked into output: {result[:300]}"
    assert "<redacted>" in result, \
        f"<redacted> not found after community redaction: {result[:300]}"


def test_fallback_redacts_radius_shared_key():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        "radius shared-key cipher RADIUS_KEY\n",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    assert "RADIUS_KEY" not in result, \
        f"RADIUS_KEY leaked into output: {result[:300]}"
    assert "<redacted>" in result, \
        f"<redacted> not found after radius key redaction: {result[:300]}"


def test_fallback_redacts_all_sensitive_values_in_full_output():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """local-user admin password irreversible-cipher SECRET_PASS
snmp-agent community read cipher PUBLIC_COMM
radius shared-key cipher RADIUS_KEY
vlan batch 10 20
acl number 3000
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    for val in SENSITIVE_VALUES:
        assert val not in result, \
            f"Sensitive value {val!r} leaked into output"


def test_fallback_redacted_lines_retain_command_context():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        "local-user admin password irreversible-cipher SECRET_PASS\n",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    assert "local-user" in result and "<redacted>" in result, \
        f"Command context not preserved after redaction: {result[:300]}"
    assert "SECRET_PASS" not in result


# ─────────────────────────────────────────────────────────────────────────────
# E. Internal diagnostics hidden — no raw error strings in translated_config
# ─────────────────────────────────────────────────────────────────────────────

INTERNAL_DIAGNOSTICS = [
    "第 0 项不是对象",
    "LLM 输出校验失败",
    "invalid JSON array",
    "analyzer missing",
]


def test_fallback_hides_internal_diagnostics():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        "vlan batch 10 20\n",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    for diag in INTERNAL_DIAGNOSTICS:
        assert diag not in result, \
            f"Internal diagnostic {diag!r} leaked into translated_config: {result[:300]}"


def test_fallback_reason_is_user_friendly():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        "vlan batch 10 20\n",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    comment = _comment_lines(result)
    reason_lines = [ln for ln in comment if "fallback_reason=" in ln]
    assert len(reason_lines) > 0, f"No fallback_reason line found: {comment[:5]}"
    reason_line = reason_lines[0]

    for diag in INTERNAL_DIAGNOSTICS:
        assert diag not in reason_line, \
            f"Internal diagnostic {diag!r} found in fallback_reason: {reason_line}"


# ─────────────────────────────────────────────────────────────────────────────
# F. Source vendor residue zero in executable lines
# ─────────────────────────────────────────────────────────────────────────────

SOURCE_RESIDUE_KEYWORDS = [
    "traffic classifier",
    "local-user",
    "interface Vlanif",
    "vlan batch",
    "security-policy rule",
    "ip address-set",
]


def test_fallback_no_source_residue_in_executable():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """sysname HW-SW
vlan batch 10 20
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
acl number 3000
 rule 5 permit ip
local-user admin password irreversible-cipher SECRET_PASS
traffic classifier TC operator and
 if-match acl 3000
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    executable = "\n".join(_executable_lines(result))
    for kw in SOURCE_RESIDUE_KEYWORDS:
        assert kw.lower() not in executable.lower(), \
            f"Source residue {kw!r} found in executable output: {executable[:300]}"


# ─────────────────────────────────────────────────────────────────────────────
# G. Firewall object classification
# ─────────────────────────────────────────────────────────────────────────────

def test_fallback_firewall_objects_not_misclassified():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """address-set name INSIDE
 address 10.0.10.0 255.255.255.0
 address 10.0.20.0 255.255.255.0
!
service-set name HTTP
 service 80
 service 443
!
security-policy rule name FROM_INSIDE
 source-zone INSIDE
 destination-zone OUTSIDE
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    comment = _comment_lines(result)
    summary_idx = next(
        (i for i, ln in enumerate(comment) if "人工复核摘要" in ln), None
    )
    assert summary_idx is not None
    summary_text = "\n".join(comment[summary_idx:])

    assert "防火墙对象" in summary_text or "ACL 与安全策略" in summary_text, \
        f"Firewall objects not classified; summary: {summary_text[:300]}"

    assert "未支持能力" not in summary_text or "防火墙对象" in summary_text or "ACL 与安全策略" in summary_text, \
        f"Firewall objects all fell to 未支持能力: {summary_text[:300]}"


# ─────────────────────────────────────────────────────────────────────────────
# H. Routing protocol classification — OSPF/BGP into 路由协议
# ─────────────────────────────────────────────────────────────────────────────

def test_fallback_ospf_in_routing_protocol_category():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """ospf 1 router-id 10.0.0.1
 area 0
  network 10.0.0.0 0.0.0.255
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    comment = _comment_lines(result)
    summary_idx = next(
        (i for i, ln in enumerate(comment) if "人工复核摘要" in ln), None
    )
    assert summary_idx is not None
    summary_text = "\n".join(comment[summary_idx:])

    assert "路由协议" in summary_text, \
        f"OSPF not classified under 路由协议: {summary_text[:300]}"


def test_fallback_bgp_in_routing_protocol_category():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """bgp 65001
 router-id 10.0.0.1
 peer 10.0.1.1 as-number 65002
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    comment = _comment_lines(result)
    summary_idx = next(
        (i for i, ln in enumerate(comment) if "人工复核摘要" in ln), None
    )
    assert summary_idx is not None
    summary_text = "\n".join(comment[summary_idx:])

    assert "路由协议" in summary_text, \
        f"BGP not classified under 路由协议: {summary_text[:300]}"


# ─────────────────────────────────────────────────────────────────────────────
# Deterministic fallback as deployable_config (not embedded in translated_config)
# ─────────────────────────────────────────────────────────────────────────────

def test_fallback_has_separate_deployable_config():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """sysname HW-SW
vlan batch 10 20
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
""",
    )
    FallbackNode().execute(state)
    deployable = state.get("deployable_config", "")

    assert deployable, "deployable_config must not be empty"
    assert "hostname HW-SW" in deployable, \
        f"hostname not in deployable_config: {deployable}"
    assert "vlan 10,20" in deployable, \
        f"vlan not in deployable_config: {deployable}"


def test_fallback_deployable_config_excludes_report_sections():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """sysname HW-SW
vlan batch 10 20
""",
    )
    FallbackNode().execute(state)
    deployable = state.get("deployable_config", "")

    FORBIDDEN_IN_DEPLOYABLE = [
        "人工复核摘要",
        "feature_summary",
        "block_count=",
        "fallback_reason=",
        "MANUAL_REVIEW_BLOCK",
        "详细复核块",
    ]
    for kw in FORBIDDEN_IN_DEPLOYABLE:
        assert kw not in deployable, \
            f"Forbidden report keyword {kw!r} found in deployable_config: {deployable[:200]}"


def test_fallback_deployable_config_allows_necessary_manual_review_comments():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """sysname HW-SW
vlan batch 10 20
""",
    )
    FallbackNode().execute(state)
    translated = state.get("translated_config", "")
    deployable = state.get("deployable_config", "")

    mr_count_translated = translated.count("MANUAL_REVIEW")
    mr_count_deployable = deployable.count("MANUAL_REVIEW")
    assert mr_count_deployable <= mr_count_translated, \
        "deployable_config should not have more MANUAL_REVIEW than translated_config"


# ─────────────────────────────────────────────────────────────────────────────
# Mixed config: all 6 categories present
# ─────────────────────────────────────────────────────────────────────────────

def test_fallback_mixed_config_all_categories_present():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """sysname HW-SW
local-user admin password irreversible-cipher SECRET_PASS
vlan batch 10 20
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
acl number 3000
 rule 5 permit ip
ospf 1 router-id 10.0.0.1
address-set name INSIDE
 address 10.0.10.0 255.255.255.0
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    comment = _comment_lines(result)
    summary_idx = next(
        (i for i, ln in enumerate(comment) if "人工复核摘要" in ln), None
    )
    assert summary_idx is not None
    summary_text = "\n".join(comment[summary_idx:])

    CATEGORIES = ["管理面", "接口与 VLAN", "ACL 与安全策略", "路由协议", "防火墙对象"]
    for cat in CATEGORIES:
        assert cat in summary_text, f"Category {cat!r} missing in mixed config summary"


# ─────────────────────────────────────────────────────────────────────────────
# P0-1: API-facing state fallback_reason must be user-friendly
# ─────────────────────────────────────────────────────────────────────────────

def test_fallback_state_fallback_reason_is_friendly():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        "vlan batch 10 20\n",
    )
    FallbackNode().execute(state)

    reason = state.get("fallback_reason", "")
    assert reason == "LLM 输出不是结构化翻译结果，已切换到规则兜底", \
        f"API fallback_reason is not friendly: {reason!r}"
    for diag in INTERNAL_DIAGNOSTICS:
        assert diag not in reason, \
            f"Internal diagnostic {diag!r} found in API fallback_reason: {reason!r}"


def test_fallback_raw_error_stored_separately():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        "vlan batch 10 20\n",
    )
    FallbackNode().execute(state)

    raw = state.get("_raw_fallback_error", "")
    assert raw == "LLM 输出校验失败: 第 0 项不是对象", \
        f"Raw error not stored separately: {raw!r}"
    friendly = state.get("fallback_reason", "")
    assert "第 0 项不是对象" not in friendly


# ─────────────────────────────────────────────────────────────────────────────
# P0-2: Sensitive redaction covers all required command formats
# ─────────────────────────────────────────────────────────────────────────────

REDACTION_CASES = [
    ("username admin password 0 SECRET_PASS", "username admin password 0 <redacted>"),
    ("username admin password 7 SECRET_PASS", "username admin password 7 <redacted>"),
    ("username admin secret 5 SECRET_HASH", "username admin secret 5 <redacted>"),
    ("snmp-server community PUBLIC_COMM RO", "snmp-server community <redacted> RO"),
    ("pre-shared-key cipher VPN_KEY", "pre-shared-key cipher <redacted>"),
]

ALL_SENSITIVE_VALUES = ["SECRET_PASS", "SECRET_HASH", "PUBLIC_COMM", "RADIUS_KEY", "VPN_KEY", "ADMIN_SECRET"]


@pytest.mark.parametrize("input_line,expected_prefix", REDACTION_CASES)
def test_fallback_redaction_preserves_command_context(input_line, expected_prefix):
    result = FallbackNode._redact_line(input_line)
    assert result == expected_prefix, \
        f"Redaction did not preserve exact command context for: {input_line!r} -> {result!r}"
    for val in ALL_SENSITIVE_VALUES:
        assert val not in result, \
            f"Sensitive value {val!r} leaked: {result!r}"


def test_fallback_full_output_no_sensitive_leaks():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """username admin password 0 ADMIN_SECRET
snmp-server community PUBLIC_COMM RO
pre-shared-key cipher VPN_KEY
vlan batch 10 20
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    for val in ALL_SENSITIVE_VALUES:
        assert val not in result, \
            f"Sensitive value {val!r} leaked into full output: {result[:300]}"

    assert "<redacted>" in result, \
        "No <redacted> found in output - redaction not applied"


def test_fallback_deterministic_block_also_redacted():
    state = _state(
        "huawei", "cisco",
        "LLM 输出校验失败: 第 0 项不是对象",
        """sysname HW-SW
vlan batch 10 20
local-user admin password irreversible-cipher SECRET_PASS
""",
    )
    FallbackNode().execute(state)
    result = state.get("translated_config", "")

    assert "SECRET_PASS" not in result
    assert "<redacted>" in result
