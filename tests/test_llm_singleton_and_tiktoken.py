import pytest
from unittest.mock import patch

def test_llm_singleton_returns_same_instance():
    # Clear any cached instance first
    import core
    core._llm_instance = None
    core._llm_settings_applied = False

    llm1 = core.get_llm()
    llm2 = core.get_llm()
    assert llm1 is llm2

def test_llm_singleton_respects_env_vars():
    import core
    core._llm_instance = None
    core._llm_settings_applied = False

    with patch.dict("os.environ", {"LLM_API_KEY": "test-key", "LLM_MODEL": "test-model", "LLM_BASE_URL": "http://test.local"}):
        llm = core.get_llm()
        assert llm.api_key == "test-key"
        assert llm.model == "test-model"
        assert llm.base_url == "http://test.local"

def test_llm_singleton_returns_error_when_no_config():
    import core
    core._llm_instance = None
    core._llm_settings_applied = False

    with patch.dict("os.environ", {}, clear=True):
        import llm_settings
        original = llm_settings.get_current_settings
        llm_settings.get_current_settings = lambda: {"api_key": "", "model": "MiniMax-M2.7", "base_url": "", "timeout": 45}
        try:
            llm = core.get_llm()
            assert llm is not None
        finally:
            llm_settings.get_current_settings = original


def test_context_compression_uses_tiktoken():
    import core.context as ctx

    pipeline = ctx.GSSCPipeline(max_context_tokens=50)

    # A string known to be longer than 50 tokens in tiktoken
    long_text = " ".join(["word"] * 300)

    result = pipeline._compress(long_text)

    # With tiktoken encoding (cl100k_base), "word " * 300 ≈ 300 tokens
    # At 50 token budget, result should be strictly shorter
    assert len(result) < len(long_text)
    assert result.endswith("截断") or result.endswith("...")


def test_context_compression_preserves_short_text():
    import core.context as ctx

    pipeline = ctx.GSSCPipeline(max_context_tokens=50)
    short = "short config text"

    result = pipeline._compress(short)

    assert result == short


def test_token_counting_is_accurate():
    import core.context as ctx

    pipeline = ctx.GSSCPipeline(max_context_tokens=10)

    # 10 tokens exactly should pass, 11 should truncate
    text_10 = " ".join(["x"] * 10)
    text_11 = " ".join(["x"] * 11)

    result_10 = pipeline._compress(text_10)
    result_11 = pipeline._compress(text_11)

    assert result_10 == text_10  # exactly at budget
    assert len(result_11) < len(text_11)  # truncated


def test_nodes_use_shared_llm_singleton(monkeypatch):
    import core
    core.reset_llm_singleton()

    mock_llm = object()
    call_count = [0]

    def fake_get_llm():
        call_count[0] += 1
        return mock_llm

    with monkeypatch.context() as m:
        m.setattr(core, "get_llm", fake_get_llm)
        # Clear any cached nodes
        import importlib
        import core.graph.nodes as nodes_mod
        importlib.reload(nodes_mod)

        from core.graph.nodes import TranslateNode, SemanticValidatorNode

        t_node = TranslateNode(llm=None)
        s_node = SemanticValidatorNode(llm=None)

        assert t_node.llm is mock_llm, f"TranslateNode.llm should be mock_llm, got {t_node.llm}"
        # SemanticValidatorNode stores llm parameter as-is (rule-based, no LLM needed)
        assert s_node.llm is None, f"SemanticValidatorNode.llm should be None when passed None"
        assert call_count[0] == 1, f"get_llm should be called once, called {call_count[0]} times"


def test_graph_agent_uses_singleton_llm(monkeypatch):
    import core
    core.reset_llm_singleton()

    mock_llm = object()

    def fake_get_llm():
        return mock_llm

    with monkeypatch.context() as m:
        m.setattr(core, "get_llm", fake_get_llm)
        import importlib
        import core.graph.nodes as nodes_mod
        importlib.reload(nodes_mod)
        import core.graph.agent as agent_mod
        importlib.reload(agent_mod)

        from core.graph.agent import GraphAgent

        agent = GraphAgent(llm=None)
        assert agent.llm is mock_llm, f"GraphAgent.llm should be mock_llm, got {agent.llm}"