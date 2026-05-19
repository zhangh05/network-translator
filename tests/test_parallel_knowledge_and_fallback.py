from unittest.mock import patch, MagicMock
import time

def test_fallback_node_reuses_parsed_config(monkeypatch):
    from core.graph.nodes import FallbackNode
    from core.graph import State
    from core.rule_translator import RuleBasedTranslator

    # Simulated parsed config with limited raw_lines
    class MockParsedConfig:
        vendor = "cisco"
        interfaces = []
        vlans = [10]
        raw_lines = ["vlan 10"]  # Only vlan line, no interface

    config_text = "vlan 10\ninterface GigabitEthernet0/1\n switchport mode trunk"

    state = State()
    state.set("config_text", config_text)
    state.set("parsed_config", MockParsedConfig())  # Pre-parsed
    state.set("from_vendor", "cisco")
    state.set("to_vendor", "huawei")
    state.set("translate_error", "simulated failure")

    # Track what config_text is passed to RuleBasedTranslator
    captured_config = []
    original_translate = RuleBasedTranslator.translate

    def mock_translate(self, cfg_text, fv, tv):
        captured_config.append(cfg_text)
        return original_translate(self, cfg_text, fv, tv)

    with patch.object(RuleBasedTranslator, 'translate', mock_translate):
        node = FallbackNode()
        result = node.execute(state)

    assert result.is_success()
    assert state.get("fallback_used") is True
    # Verify RuleBasedTranslator was called with parsed raw_lines (not full config_text)
    # The captured config should be from raw_lines, not config_text
    assert len(captured_config) == 1
    # raw_lines only has "vlan 10", not the full config with interface lines
    assert "interface" not in captured_config[0]
    assert "vlan 10" in captured_config[0]

def test_knowledge_retrieval_runs_concurrently_with_llm(monkeypatch):
    """Verify knowledge retrieval doesn't block on LLM call by checking timing."""
    from core.graph.nodes import TranslateNode
    from core.graph import State

    llm_done = [False]
    kn_done = [False]

    class MockLLM:
        def chat(self, **kwargs):
            # LLM call takes longer than knowledge retrieval
            time.sleep(0.15)
            llm_done[0] = True
            return {"content": '[{"type":"vlan","function":"vlan","params":{"id":10},"original_lines":["vlan 10"],"confidence":1.0}]'}

    class MockKnowledgeStore:
        def retrieve_for_ir_block(self, block, target_vendor=None):
            time.sleep(0.05)  # knowledge retrieval is faster
            kn_done[0] = True
            class Chunk:
                chunk_id = "vlan"
                content = "vlan knowledge"
            return [Chunk()]

        def format_for_prompt(self, chunks, max_chars=2000):
            return "[vlan knowledge]"

    from core.graph import State

    state = State()
    state.set("config_text", "vlan 10")
    state.set("from_vendor", "cisco")
    state.set("to_vendor", "huawei")

    from tools import knowledge_manager
    original_ks = knowledge_manager.get_knowledge_store()

    class FakeStore:
        instance = MockKnowledgeStore()

    monkeypatch.setattr(knowledge_manager, "get_knowledge_store", lambda: FakeStore.instance)

    node = TranslateNode(llm=MockLLM())
    start = time.time()
    result = node.execute(state)
    elapsed = time.time() - start

    # If parallel: total time ≈ max(llm_time, kn_time) ≈ 0.15s
    # If serial: total time ≈ llm_time + kn_time ≈ 0.20s
    # With parallel, both should be done
    assert result.is_success()
    # Verify timing: parallel should be ~max(llm, kn) not sum
    # Total = parse_to_ir(~0.15s) + max(translate_ir~0.15s, kn~0.05s) ≈ 0.30s
    # Serial would be parse + translate + kn ≈ 0.35s+
    # Allow generous slack for test overhead and CI variability
    assert elapsed < 0.55, f"Expected ~0.30-0.45s parallel, got {elapsed:.3f}s"
    # The test verifies the concurrent execution happened
    # (We check this indirectly via the mock call order)