import tempfile

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
    agent = GraphAgent(llm=ErrorLLM(), cache_dir=tempfile.mkdtemp())

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
    agent = GraphAgent(llm=InvalidJsonLLM(), cache_dir=tempfile.mkdtemp())

    result = agent.run(
        config_text="""interface GigabitEthernet1/0/1
 port link-type trunk
 port trunk permit vlan 20 30
""",
        from_vendor="h3c",
        to_vendor="huawei",
    )

    assert result["fallback_used"] is True
    assert "port trunk allow-pass vlan 20 30" in (result.get("deployable_config") or result["translated"])


def test_network_translator_agent_passes_configured_llm_to_graph_nodes():
    llm = ErrorLLM()
    agent = NetworkTranslatorAgent(llm=llm)

    translate_node = agent.graph_agent.graph.nodes["translate"]
    semantic_node = agent.graph_agent.graph.nodes["semantic_validate"]

    assert translate_node.llm is llm
    assert semantic_node.llm is llm


class TestCapabilityGapNodeAnalyzerIntegration:
    """P1-2: CapabilityGapNode must handle list-type analyzer_results."""

    def test_analyzer_list_injects_capability_gap(self):
        from core.graph.nodes import CapabilityGapNode
        state = State()
        state.set("config_text", "ip nat inside source list 10 pool P overload\n")
        state.set("from_vendor", "cisco")
        state.set("to_vendor", "huawei")
        state.set("analyzer_results", [
            {
                "feature": "nat",
                "status": "analyzed",
                "risk_level": "warning",
                "summary": "missing NAT reference",
                "source_lines": ["ip nat inside source list 10 pool P overload"],
                "details": {"missing_references": ["ACL 10"]},
            }
        ])
        node = CapabilityGapNode()
        result = node.execute(state)
        assert result.is_success()
        gaps = state.get("capability_gaps", [])
        analyzer_gaps = [g for g in gaps if g["feature"].startswith("analyzer:")]
        assert len(analyzer_gaps) > 0, "No analyzer gaps found"
        nat_gap = next((g for g in analyzer_gaps if "nat" in g["feature"]), None)
        assert nat_gap is not None, f"Expected analyzer:nat gap, got features: {[g['feature'] for g in analyzer_gaps]}"
        assert nat_gap["severity"] == "warning"
        assert nat_gap["source_lines"] == ["ip nat inside source list 10 pool P overload"]
        assert nat_gap["details"]["missing_references"] == ["ACL 10"]

    def test_analyzer_list_fatal_creates_gap(self):
        from core.graph.nodes import CapabilityGapNode
        state = State()
        state.set("config_text", "object-group network A\n network-object object B\n")
        state.set("from_vendor", "cisco")
        state.set("to_vendor", "huawei")
        state.set("analyzer_results", [
            {
                "feature": "object",
                "status": "analyzed",
                "risk_level": "fatal",
                "summary": "circular reference detected",
                "source_lines": ["object-group network A", "object-group network B"],
                "details": {"circular_ref": True},
            }
        ])
        node = CapabilityGapNode()
        result = node.execute(state)
        assert result.is_success()
        gaps = state.get("capability_gaps", [])
        object_gap = next((g for g in gaps if g["feature"].startswith("analyzer:") and "object" in g["feature"]), None)
        assert object_gap is not None
        assert object_gap["severity"] == "fatal"

    def test_analyzer_list_info_does_not_create_gap(self):
        from core.graph.nodes import CapabilityGapNode
        state = State()
        state.set("config_text", "hostname R1\n")
        state.set("from_vendor", "cisco")
        state.set("to_vendor", "huawei")
        state.set("analyzer_results", [
            {
                "feature": "system",
                "status": "analyzed",
                "risk_level": "info",
                "summary": "system config",
                "source_lines": ["hostname R1"],
                "details": {},
            }
        ])
        node = CapabilityGapNode()
        result = node.execute(state)
        assert result.is_success()
        gaps = state.get("capability_gaps", [])
        analyzer_gaps = [g for g in gaps if g["feature"].startswith("analyzer:")]
        assert len(analyzer_gaps) == 0, f"Expected no analyzer gaps for info risk, got {analyzer_gaps}"
