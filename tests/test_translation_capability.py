from core.graph import State
from core.graph.agent import GraphAgent
from core.graph.nodes import ParseNode
from agents import NetworkTranslatorAgent


class ErrorLLM:
    def chat(self, *args, **kwargs):
        return {"error": "simulated outage", "content": ""}


class InvalidJsonLLM:
    def chat(self, *args, **kwargs):
        return {"content": "not json", "tool_calls": []}


def test_parse_node_respects_explicit_vendor_for_ambiguous_config():
    state = State()
    state.set("config_text", "vlan 10\n")
    state.set("from_vendor", "cisco")

    result = ParseNode().execute(state)

    assert result.is_success()
    assert state.get("from_vendor") == "cisco"


def test_graph_agent_uses_rule_fallback_when_llm_is_unavailable():
    agent = GraphAgent(llm=ErrorLLM())

    result = agent.run(
        config_text="""hostname SW1
vlan 10
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk allowed vlan 10
 spanning-tree portfast
""",
        from_vendor="cisco",
        to_vendor="huawei",
    )

    assert result["fallback_used"] is True
    assert "```huawei" in result["translated"]
    assert "sysname SW1" in result["translated"]
    assert "vlan 10" in result["translated"]
    assert "port link-type trunk" in result["translated"]
    assert "port trunk allow-pass vlan 10" in result["translated"]
    assert "stp edged-port enable" in result["translated"]


def test_invalid_llm_json_falls_back_to_rule_translation():
    agent = GraphAgent(llm=InvalidJsonLLM())

    result = agent.run(
        config_text="""interface GigabitEthernet1/0/1
 port link-type trunk
 port trunk permit vlan 20 30
""",
        from_vendor="h3c",
        to_vendor="huawei",
    )

    assert result["fallback_used"] is True
    assert "port trunk allow-pass vlan 20 30" in result["translated"]


def test_network_translator_agent_passes_configured_llm_to_graph_nodes():
    llm = ErrorLLM()
    agent = NetworkTranslatorAgent(llm=llm)

    translate_node = agent.graph_agent.graph.nodes["translate"]
    semantic_node = agent.graph_agent.graph.nodes["semantic_validate"]

    assert translate_node.llm is llm
    assert semantic_node.llm is llm
