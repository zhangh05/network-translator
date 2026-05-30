import json
import tempfile

from core.graph import State
from core.graph.agent import GraphAgent
from core.graph.nodes import FallbackNode
from core.module_graph import build_module_graph, ordered_modules, assemble_source_modules


SAMPLE_CONFIG = """sysname HW-SW
vlan batch 10 20 101 to 102
#
acl number 3000
 rule 5 permit ip
#
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
 traffic-filter inbound acl 3000
#
interface GigabitEthernet0/0/1
 port link-type trunk
 port trunk allow-pass vlan 10 20
#
ospf 1 router-id 10.0.0.1
 area 0.0.0.0
  network 10.0.10.0 0.0.0.255
#
voice-vlan mac-address 0027-0000-0000 mask ffff-0000-0000
"""


def test_build_module_graph_extracts_feature_modules_with_source_spans():
    graph = build_module_graph(SAMPLE_CONFIG, vendor="huawei")

    assert len(graph.modules) >= 6
    assert graph.by_feature("vlan")
    assert graph.by_feature("acl")
    assert graph.by_feature("interface")
    assert graph.by_feature("ospf")
    assert all(module.start_line <= module.end_line for module in graph.modules)
    assert all(module.source_lines for module in graph.modules)


def test_vlan_module_provides_each_vlan_from_batch_and_range():
    graph = build_module_graph(SAMPLE_CONFIG, vendor="huawei")
    vlan_module = graph.by_feature("vlan")[0]

    assert {"vlan:10", "vlan:20", "vlan:101", "vlan:102"}.issubset(set(vlan_module.provides))
    assert vlan_module.status == "translatable"


def test_svi_and_acl_binding_modules_depend_on_their_providers():
    graph = build_module_graph(SAMPLE_CONFIG, vendor="huawei")
    svi_module = next(module for module in graph.by_feature("interface") if "svi" in module.tags)
    acl_module = graph.by_feature("acl")[0]
    vlan_module = graph.by_feature("vlan")[0]

    assert "vlan:10" in svi_module.consumes
    assert "acl:3000" in svi_module.consumes
    assert vlan_module.module_id in svi_module.depends_on
    assert acl_module.module_id in svi_module.depends_on
    assert any(edge.from_module == svi_module.module_id and edge.to_module == vlan_module.module_id for edge in graph.edges)
    assert any(edge.from_module == svi_module.module_id and edge.to_module == acl_module.module_id for edge in graph.edges)


def test_trunk_interface_records_vlan_consumes_and_trunk_tag():
    graph = build_module_graph(SAMPLE_CONFIG, vendor="huawei")
    trunk_module = next(module for module in graph.by_feature("interface") if "trunk" in module.tags)

    assert {"vlan:10", "vlan:20"}.issubset(set(trunk_module.consumes))
    assert "trunk" in trunk_module.tags


def test_ospf_module_preserves_process_identity_and_source_lines():
    graph = build_module_graph(SAMPLE_CONFIG, vendor="huawei")
    ospf_module = graph.by_feature("ospf")[0]

    assert "ospf:1" in ospf_module.provides
    assert ospf_module.source_lines[0].startswith("ospf 1")
    assert any("network 10.0.10.0" in line for line in ospf_module.source_lines)


def test_vendor_specific_unknown_feature_becomes_manual_review_module():
    graph = build_module_graph(SAMPLE_CONFIG, vendor="huawei")
    review_modules = graph.manual_review_modules()

    assert any("voice-vlan" in "\n".join(module.source_lines) for module in review_modules)
    assert any(module.feature == "unknown" for module in review_modules)
    assert all(module.manual_review_reason for module in review_modules)


def test_module_graph_to_dict_is_json_serializable():
    graph = build_module_graph(SAMPLE_CONFIG, vendor="huawei")

    payload = graph.to_dict()
    encoded = json.dumps(payload, ensure_ascii=False)

    assert "modules" in payload
    assert "edges" in payload
    assert "vlan:10" in encoded
    assert "manual_review_reason" in encoded


def test_ordered_modules_places_providers_before_consumers():
    config = """interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
 traffic-filter inbound acl 3000
#
acl number 3000
 rule 5 permit ip
#
vlan batch 10
"""
    graph = build_module_graph(config, vendor="huawei")
    ordered = ordered_modules(graph)
    positions = {module.module_id: index for index, module in enumerate(ordered)}
    svi_module = next(module for module in graph.by_feature("interface") if "svi" in module.tags)
    acl_module = graph.by_feature("acl")[0]
    vlan_module = graph.by_feature("vlan")[0]

    assert positions[vlan_module.module_id] < positions[svi_module.module_id]
    assert positions[acl_module.module_id] < positions[svi_module.module_id]


def test_assemble_source_modules_returns_dependency_ordered_sections():
    config = """interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
 traffic-filter inbound acl 3000
#
acl number 3000
 rule 5 permit ip
#
vlan batch 10
"""
    graph = build_module_graph(config, vendor="huawei")

    assembled = assemble_source_modules(graph)

    assert assembled.sections[0].feature == "acl" or assembled.sections[0].feature == "vlan"
    assert assembled.text.index("vlan batch 10") < assembled.text.index("interface Vlanif10")
    assert assembled.text.index("acl number 3000") < assembled.text.index("interface Vlanif10")
    assert "### module" in assembled.text
    assert "depends_on" in assembled.text


def test_safe_fallback_metadata_includes_module_graph_for_review_ui():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")
    state.set("config_text", SAMPLE_CONFIG)

    FallbackNode().execute(state)
    metadata = state.get("_fallback_metadata")
    module_graph = metadata["module_graph"]
    module_summary = metadata["module_summary"]

    assert module_summary["vlan"] == 1
    assert module_summary["acl"] == 1
    assert module_summary["interface"] == 2
    assert module_summary["ospf"] == 1
    assert module_graph["modules"]
    assert any("vlan:10" in module["provides"] for module in module_graph["modules"])
    assert any("acl:3000" in module["consumes"] for module in module_graph["modules"])
    assert any(edge["label"] == "acl:3000" for edge in module_graph["edges"])


def test_safe_fallback_module_graph_keeps_manual_review_source_evidence_in_metadata():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")
    state.set("config_text", SAMPLE_CONFIG)

    FallbackNode().execute(state)
    deployable = state.get("deployable_config", "")
    modules = state.get("_fallback_metadata")["module_graph"]["modules"]

    assert "MANUAL_REVIEW" in deployable
    assert any(
        module["status"] == "manual_review" and "voice-vlan" in "\n".join(module["source_lines"])
        for module in modules
    )


def test_graph_agent_result_exposes_module_graph_for_api_consumers():
    class NonObjectListLLM:
        def chat(self, *args, **kwargs):
            return {"content": '["not an object"]', "tool_calls": []}

    agent = GraphAgent(
        llm=NonObjectListLLM(),
        cache_dir=tempfile.mkdtemp(),
        memory_dir=tempfile.mkdtemp(),
    )

    result = agent.run(SAMPLE_CONFIG, from_vendor="huawei", to_vendor="cisco")

    assert result["fallback_used"] is True
    assert result["module_summary"]["vlan"] == 1
    assert result["module_graph"]["modules"]
    assert any(edge["label"] == "vlan:10" for edge in result["module_graph"]["edges"])
