from pathlib import Path
from unittest.mock import patch
import tempfile

from core.graph import State
from core.graph.agent import GraphAgent
from core.graph.nodes import FallbackNode
from core.rule_translator import RuleBasedTranslator


HUAWEI_SAMPLE = Path("/Users/zhangh01/Desktop/1.txt")


def _executable_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip()
        and not line.strip().startswith(("!", "#", "```"))
    ]


def test_block_splitter_classifies_real_huawei_config_features():
    from core.parser.block_splitter import split_config_by_feature

    config_text = HUAWEI_SAMPLE.read_text(encoding="utf-8")
    blocks = split_config_by_feature(config_text, vendor="huawei")
    features = {block.feature for block in blocks}

    assert len(blocks) > 40
    assert {"vlan", "interface", "acl", "qos", "aaa", "snmp", "nqa", "bfd", "vrf"}.issubset(features)
    assert all(block.start_line <= block.end_line for block in blocks)


def test_block_splitter_classifies_cisco_h3c_huawei_common_blocks():
    from core.parser.block_splitter import split_config_by_feature

    config_text = """
hostname SW1
vlan 10
interface GigabitEthernet1/0/1
 switchport mode trunk
ip access-list extended ACL-IN
 permit ip any any
ip route 0.0.0.0 0.0.0.0 10.0.0.1
class-map match-any CM
policy-map PM
snmp-server community public RO
#
sysname H3C1
vlan 20
interface Vlan-interface20
 ip address 10.0.20.1 255.255.255.0
acl number 3000
 rule 5 permit ip
traffic classifier TC operator and
traffic behavior TB
traffic policy TP
local-user admin class manage
#
sysname HW1
vlan batch 30 40
interface Vlanif30
 ip address 10.0.30.1 255.255.255.0
ip vpn-instance MGMT
snmp-agent community read cipher xxx
nqa test-instance admin ping
bfd
"""
    blocks = split_config_by_feature(config_text, vendor="auto")
    features = {block.feature for block in blocks}

    assert {"system", "vlan", "interface", "acl", "route", "qos", "aaa", "snmp", "nqa", "bfd", "vrf"}.issubset(features)


def test_llm_validation_failure_fallback_never_emits_source_vendor_executable_lines():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")
    state.set(
        "config_text",
        """info-center source default channel 2 log level warning
vlan batch 10 20 30
traffic classifier TC operator and
 if-match acl 3000
traffic behavior TB
 redirect ip-nexthop 10.0.0.1
local-user admin password irreversible-cipher x
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
""",
    )

    result = FallbackNode().execute(state)
    translated = state.get("translated_config")
    executable = "\n".join(_executable_lines(translated))

    assert result.is_success()
    assert state.get("fallback_used") is True
    assert state.get("safe_fallback") is True
    assert state.get("manual_review_required") is True
    assert state.get("_route_outcome") == "fallback_manual_review"
    assert "MANUAL_REVIEW" in translated
    assert "info-center source" not in executable
    assert "vlan batch" not in executable
    assert "traffic classifier" not in executable
    assert "traffic behavior" not in executable
    assert "local-user" not in executable
    assert "interface Vlanif10" not in executable
    assert state.get("fallback_reason") == "LLM 输出不是结构化翻译结果，已切换到规则兜底"
    assert "第 0 项不是对象" not in translated


def test_safe_fallback_summarizes_non_json_array_error_for_users():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: LLM 输出不包含 JSON 数组")
    state.set("config_text", "sysname HW1\nvlan batch 10 20\n")

    FallbackNode().execute(state)
    translated = state.get("translated_config")

    assert state.get("fallback_reason") == "LLM 输出不是结构化翻译结果，已切换到规则兜底"
    assert "不包含 JSON 数组" not in translated


def test_small_non_validation_error_keeps_rule_based_fallback_behavior():
    class MockParsedConfig:
        raw_lines = ["vlan 10"]

    state = State()
    state.set("config_text", "vlan 10\ninterface GigabitEthernet0/1")
    state.set("parsed_config", MockParsedConfig())
    state.set("from_vendor", "cisco")
    state.set("to_vendor", "huawei")
    state.set("translate_error", "simulated provider outage")

    captured = []
    original_translate = RuleBasedTranslator.translate

    def mock_translate(self, cfg_text, from_vendor, to_vendor):
        captured.append(cfg_text)
        return original_translate(self, cfg_text, from_vendor, to_vendor)

    with patch.object(RuleBasedTranslator, "translate", mock_translate):
        result = FallbackNode().execute(state)

    assert result.is_success()
    assert captured == ["vlan 10"]
    assert state.get("safe_fallback") in (None, False)
    assert "vlan 10" in state.get("translated_config")


def test_graph_agent_uses_safe_fallback_when_llm_returns_non_object_items():
    class NonObjectListLLM:
        def chat(self, *args, **kwargs):
            return {"content": '["not an object"]', "tool_calls": []}

    agent = GraphAgent(
        llm=NonObjectListLLM(),
        cache_dir=tempfile.mkdtemp(),
        memory_dir=tempfile.mkdtemp(),
    )

    result = agent.run(
        config_text="""vlan batch 10 20
traffic classifier TC operator and
 if-match acl 3000
local-user admin password irreversible-cipher x
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
""",
        from_vendor="huawei",
        to_vendor="cisco",
    )
    executable = "\n".join(_executable_lines(result["translated"]))

    assert result["fallback_used"] is True
    assert result["validation"]["deployable"] is False
    assert result["validation"]["manual_review_required"] is True
    assert "MANUAL_REVIEW" in result["translated"]
    assert "vlan batch" not in executable
    assert "traffic classifier" not in executable
    assert "local-user" not in executable
    assert "interface Vlanif10" not in executable


def test_safe_fallback_emits_deterministic_translation_for_known_huawei_blocks():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")
    state.set(
        "config_text",
        """sysname HW-SW
vlan batch 10 20
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
ip route-static 0.0.0.0 0.0.0.0 10.0.10.254
traffic classifier TC operator and
 if-match acl 3000
 """,
    )

    FallbackNode().execute(state)
    translated = state.get("translated_config")
    deployable = state.get("deployable_config", "")
    executable = "\n".join(_executable_lines(deployable))

    assert "hostname HW-SW" in executable
    assert "vlan 10,20" in executable
    assert "interface Vlan10" in executable
    assert "ip address 10.0.10.1 255.255.255.0" in executable
    assert "ip route 0.0.0.0 0.0.0.0 10.0.10.254" in executable
    assert "! MANUAL_REVIEW" in translated
    assert "traffic classifier TC" not in executable
    assert "if-match acl" not in executable


def test_safe_fallback_emits_grouped_human_readable_summary():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")
    state.set(
        "config_text",
        """sysname HW-SW
vlan batch 10 20
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
traffic classifier TC operator and
 if-match acl 3000
traffic behavior TB
local-user admin password irreversible-cipher x
acl number 3000
 rule 5 permit ip
snmp-agent community read cipher public
""",
    )

    FallbackNode().execute(state)
    translated = state.get("translated_config")
    deployable = state.get("deployable_config", "")
    executable = "\n".join(_executable_lines(deployable))

    assert "人工复核摘要" in translated
    assert "管理面" in translated or "aaa" in translated.lower()
    assert "ACL 与安全策略" in translated or "acl" in translated.lower()
    assert "MANUAL_REVIEW_BLOCK" not in translated, "detail blocks must not appear in user report"
    assert "fallback_reason=" not in translated, "internal metadata must not appear in user report"
    assert "block_count=" not in translated, "internal metadata must not appear in user report"
    assert "hostname HW-SW" in executable
    assert "vlan 10,20" in executable
    assert "interface Vlan10" in executable


def test_safe_fallback_detail_blocks_capped_at_20():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")

    lines = []
    for i in range(1, 51):
        lines.append(f"interface Vlanif{i}")
        lines.append(f" ip address 10.0.{i}.1 255.255.255.0")

    state.set("config_text", "\n".join(lines))

    FallbackNode().execute(state)
    translated = state.get("translated_config")

    metadata = state.get("_fallback_metadata", {})
    total = metadata.get("block_count", 0)
    assert total == 50, f"Expected 50 blocks in metadata, got {total}"

    assert "MANUAL_REVIEW_BLOCK" not in translated, \
        "detail blocks must not appear in user-facing report"


def test_safe_fallback_sample_lines_are_comments_not_executable():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")
    state.set(
        "config_text",
        """sysname HW-SW
vlan batch 10 20
aaa
 local-user admin password irreversible-cipher x
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
""",
    )

    FallbackNode().execute(state)
    translated = state.get("translated_config")
    executable = "\n".join(_executable_lines(translated))

    assert "示例：" in translated
    assert "local-user" not in executable
    assert "vlan batch" not in executable
    assert "interface Vlanif10" not in executable
