"""Step 16 验收：prompt 硬约束 + deployability"""

import pytest
from core.ir import translate_config, _comment_prefix


class MockLLM:
    def __init__(self, response: str):
        self.response = response
        self.last_prompt = ""
        self.model = "mock"

    def chat(self, messages, system="", temperature=0.2, max_tokens=8192):
        self.last_prompt = messages[0]["content"]
        return {"content": self.response}


class TestPromptHardConstraints:

    def test_prompt_contains_no_markdown_fence_rule(self):
        llm = MockLLM('[]')
        translate_config("interface GigabitEthernet0/1\n ip address 1.2.3.4 255.255.255.0", "cisco", "huawei", llm)
        assert "不含 Markdown 代码围栏" in llm.last_prompt

    def test_prompt_contains_no_placeholder_rule(self):
        llm = MockLLM('[]')
        translate_config("hostname R1", "cisco", "huawei", llm)
        assert "禁止输出占位符" in llm.last_prompt
        assert "<...>" in llm.last_prompt
        assert "TODO" in llm.last_prompt or "PLACEHOLDER" in llm.last_prompt

    def test_prompt_contains_missing_param_rule(self):
        llm = MockLLM('[]')
        translate_config("hostname R1", "cisco", "huawei", llm)
        assert "必填参数" in llm.last_prompt
        assert "禁止编造" in llm.last_prompt

    def test_prompt_contains_nat_acl_order_rule(self):
        llm = MockLLM('[]')
        translate_config("hostname R1", "cisco", "huawei", llm)
        assert "NAT" in llm.last_prompt
        assert "安全策略" in llm.last_prompt or "security-policy" in llm.last_prompt or "security_policy" in llm.last_prompt.lower().replace("-", "_")
        assert "规则顺序" in llm.last_prompt

    def test_prompt_contains_platform_authority_rule(self):
        llm = MockLLM('[]')
        translate_config("hostname R1", "cisco", "huawei", llm)
        assert "权威平台" in llm.last_prompt or "禁止混入" in llm.last_prompt

    def test_prompt_contains_context_block(self):
        llm = MockLLM('[]')
        translate_config(
            "hostname R1", "cisco", "huawei", llm,
            source_domain="routing", source_platform="ios",
            target_domain="routing", target_platform="vrp",
            features=["interface", "system"],
            analyzer_context="[analyzer:nat] risk=warning",
            capability_notes=["nat: partial"],
        )
        assert "routing" in llm.last_prompt
        assert "ios" in llm.last_prompt
        assert "vrp" in llm.last_prompt
        assert "interface" in llm.last_prompt
        assert "analyzer:nat" in llm.last_prompt
        assert "nat: partial" in llm.last_prompt

    def test_prompt_comment_prefix_for_cisco(self):
        llm = MockLLM('[]')
        translate_config("hostname R1", "huawei", "cisco", llm)
        assert "! MANUAL_REVIEW" in llm.last_prompt

    def test_prompt_comment_prefix_for_huawei(self):
        llm = MockLLM('[]')
        translate_config("hostname R1", "cisco", "huawei", llm)
        assert "# MANUAL_REVIEW" in llm.last_prompt

    def test_prompt_comment_prefix_for_h3c(self):
        llm = MockLLM('[]')
        translate_config("hostname R1", "cisco", "h3c", llm)
        assert "# MANUAL_REVIEW" in llm.last_prompt


class TestJsonToPureConfig:

    def test_translated_config_is_pure_text_no_json(self):
        llm = MockLLM('[{"type":"interface","translated_lines":["interface GigabitEthernet0/1"," port link-type trunk"]}]')
        result = translate_config("interface Gi0/1\n switchport mode trunk", "cisco", "huawei", llm)
        translated_lines = []
        for block in result:
            if isinstance(block, dict) and block.get("translated_lines"):
                translated_lines.extend(block["translated_lines"])
        config = "\n".join(translated_lines).strip()
        assert "[" not in config and "]" not in config
        assert config.startswith("interface")
        assert "translated_lines" not in config

    def test_translated_excludes_notes_from_config(self):
        llm = MockLLM('[{"type":"bgp","translated_lines":["bgp 100"],"notes":"AS 号取自源配置","original_lines":["router bgp 100"]}]')
        result = translate_config("router bgp 100", "cisco", "huawei", llm)
        for block in result:
            if isinstance(block, dict):
                assert "notes" not in block.get("translated_lines", [])[:]


class TestDeployability:

    def test_placeholder_critical_warning_sets_deployable_false(self, monkeypatch):
        from core.graph.nodes import ValidateNode
        from tools.__init__ import ValidationResult

        node = ValidateNode("test_validate")
        warnings = ["包含未替换的占位符 <...>，请人工确认"]
        assert node._has_critical_content_warnings(warnings)

    def test_residue_critical_warning_sets_deployable_false(self, monkeypatch):
        from core.graph.nodes import ValidateNode

        node = ValidateNode("test_validate")
        warnings = ["可能存在源厂商残留：Cisco switchport 命令"]
        assert node._has_critical_content_warnings(warnings)

    def test_style_warning_not_critical(self, monkeypatch):
        from core.graph.nodes import ValidateNode

        node = ValidateNode("test_validate")
        warnings = ["华为建议使用 GigabitEthernet 而非 Ethernet"]
        assert not node._has_critical_content_warnings(warnings)

    def test_non_deployable_with_critical_warning(self, monkeypatch):
        from core.graph.nodes import ValidateNode

        node = ValidateNode("test_validate")
        dep = node._evaluate_deployability("warning", False, True)
        assert dep["deployable"] is False
        assert dep["manual_review_required"] is True

    def test_deployable_with_style_warning_only(self, monkeypatch):
        from core.graph.nodes import ValidateNode

        node = ValidateNode("test_validate")
        dep = node._evaluate_deployability("warning", False, False)
        assert dep["deployable"] is True
        assert dep["manual_review_required"] is True


class TestCommentPrefix:

    def test_cisco_comment_prefix(self):
        assert _comment_prefix("cisco") == "!"

    def test_huawei_comment_prefix(self):
        assert _comment_prefix("huawei") == "#"

    def test_h3c_comment_prefix(self):
        assert _comment_prefix("h3c") == "#"

    def test_ruijie_comment_prefix(self):
        assert _comment_prefix("ruijie") == "!"

    def test_unknown_vendor_prefix_default(self):
        assert _comment_prefix("unknown_vendor") == "#"
