"""Tests for prompt versioning in core/ir.py"""

import core.ir as ir


def test_prompt_version_defined():
    assert hasattr(ir, "PROMPT_VERSION"), "PROMPT_VERSION constant must be defined"
    assert isinstance(ir.PROMPT_VERSION, str), "PROMPT_VERSION must be a string"
    assert len(ir.PROMPT_VERSION) > 0, "PROMPT_VERSION must not be empty"


def test_prompt_version_included_in_translate_config():
    """The _meta entry for translate_config output must contain prompt_version."""
    class FakeLLM:
        def chat(self, messages, system, temperature, max_tokens):
            prompt = messages[0]["content"]
            assert "prompt_version:" in prompt, "prompt_version must appear in prompt"
            assert ir.PROMPT_VERSION in prompt, "actual PROMPT_VERSION must be in prompt"
            return {"content": '[{"type": "interface", "translated_lines": ["interface GigabitEthernet0/0"], "original_lines": ["interface GigabitEthernet0/0"], "notes": "", "confidence": 1.0}]'}

    result = ir.translate_config(
        config_text="interface GigabitEthernet0/0\n ip address 1.2.3.4 255.255.255.0",
        from_vendor="cisco",
        to_vendor="huawei",
        llm=FakeLLM(),
    )
    assert isinstance(result, list)
    assert len(result) >= 2
    meta_entries = [e for e in result if e.get("type") == "_meta"]
    assert len(meta_entries) >= 1
    assert meta_entries[0].get("prompt_version") == ir.PROMPT_VERSION


def test_prompt_version_included_in_parse_to_ir():
    class FakeLLM:
        def chat(self, messages, system, temperature, max_tokens):
            prompt = messages[0]["content"]
            assert "prompt_version:" in prompt
            assert ir.PROMPT_VERSION in prompt
            return {"content": '[]'}

    result = ir.parse_to_ir(
        config_text="interface GigabitEthernet0/0\n ip address 1.2.3.4 255.255.255.0",
        vendor="cisco",
        llm=FakeLLM(),
    )
    assert isinstance(result, list)
    assert result[0].get("type") == "_meta"
    assert result[0].get("prompt_version") == ir.PROMPT_VERSION


def test_prompt_version_included_in_backtranslate():
    class FakeLLM:
        def chat(self, messages, system, temperature, max_tokens):
            prompt = messages[0]["content"]
            assert "prompt_version:" in prompt
            assert ir.PROMPT_VERSION in prompt
            return {"content": '[]'}

    result = ir.backtranslate_to_ir(
        translated_config="interface GigabitEthernet0/0",
        target_vendor="cisco",
        llm=FakeLLM(),
    )
    assert isinstance(result, list)
    assert result[0].get("type") == "_meta"
    assert result[0].get("prompt_version") == ir.PROMPT_VERSION


def test_prompt_version_included_in_compare_ir():
    class FakeLLM:
        def chat(self, messages, system, temperature, max_tokens):
            prompt = messages[0]["content"]
            assert "prompt_version:" in prompt
            assert ir.PROMPT_VERSION in prompt
            return {"content": '{"overall_match": true, "matched_blocks": [], "unmatched_source": [], "summary": "ok"}'}

    result = ir.compare_ir(
        ir_source=[{"type": "interface", "function": "config", "params": {"name": "G0/0"}}],
        ir_back=[{"type": "interface", "function": "config", "params": {"name": "G0/0"}}],
        llm=FakeLLM(),
    )
    assert isinstance(result, dict)
    assert result.get("overall_match") is True
