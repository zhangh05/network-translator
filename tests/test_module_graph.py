import json
import tempfile

from core.graph import State
from core.graph.agent import GraphAgent
from core.graph.nodes import FallbackNode
from core.module_graph import build_module_graph, ordered_modules, assemble_source_modules, translate_module_graph


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
    assert graph.by_feature("interface.svi")
    assert graph.by_feature("interface.physical")
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
    svi_module = graph.by_feature("interface.svi")[0]
    binding_module = graph.by_feature("acl_binding")[0]
    acl_module = graph.by_feature("acl")[0]
    vlan_module = graph.by_feature("vlan")[0]

    assert "vlan:10" in svi_module.consumes
    assert "acl:3000" in binding_module.consumes
    assert "interface:Vlanif10" in binding_module.consumes
    assert vlan_module.module_id in svi_module.depends_on
    assert acl_module.module_id in binding_module.depends_on
    assert svi_module.module_id in binding_module.depends_on
    assert any(edge.from_module == svi_module.module_id and edge.to_module == vlan_module.module_id for edge in graph.edges)
    assert any(edge.from_module == binding_module.module_id and edge.to_module == acl_module.module_id for edge in graph.edges)
    assert any(coupling["relation"] == "binds_acl_to_interface" for coupling in graph.to_dict()["couplings"])


def test_trunk_interface_records_vlan_consumes_and_trunk_tag():
    graph = build_module_graph(SAMPLE_CONFIG, vendor="huawei")
    trunk_module = graph.by_feature("interface.physical")[0]

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
    svi_module = graph.by_feature("interface.svi")[0]
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
    assert module_summary["interface.svi"] == 1
    assert module_summary["interface.physical"] == 1
    assert module_summary["acl_binding"] == 1
    assert module_summary["ospf"] == 1
    assert module_graph["modules"]
    assert any("vlan:10" in module["provides"] for module in module_graph["modules"])
    assert any("acl:3000" in module["consumes"] for module in module_graph["modules"])
    assert any(edge["label"] == "acl:3000" for edge in module_graph["edges"])
    assert any(coupling["relation"] == "binds_acl_to_interface" for coupling in module_graph["couplings"])


def test_safe_fallback_module_graph_keeps_manual_review_source_evidence_in_metadata():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")
    state.set("config_text", SAMPLE_CONFIG)

    FallbackNode().execute(state)
    deployable = state.get("deployable_config", "")
    metadata = state.get("_fallback_metadata")
    modules = metadata["module_graph"]["modules"]

    assert "MANUAL_REVIEW" not in deployable
    assert "voice-vlan" not in deployable
    assert "voice-vlan" in metadata["manual_review_config"]
    assert metadata["module_translations"]["results"]
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


def test_translate_module_graph_separates_deployable_and_manual_review_outputs():
    graph = build_module_graph(SAMPLE_CONFIG, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")

    assert "hostname HW-SW" in assembly.deployable_config
    assert "vlan 10,20,101-102" in assembly.deployable_config
    assert "interface Vlan10" in assembly.deployable_config
    assert "ip access-group 3000 in" in assembly.deployable_config
    assert "MANUAL_REVIEW" not in assembly.deployable_config
    assert "voice-vlan" in assembly.manual_review_config
    assert any(item.module_id for item in assembly.results)
    assert any(item.status == "manual_review" for item in assembly.results)


def test_translate_module_graph_preserves_dependency_order_in_deployable_config():
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

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")

    assert assembly.deployable_config.index("vlan 10") < assembly.deployable_config.index("interface Vlan10")
    assert assembly.deployable_config.index("ip access-list") < assembly.deployable_config.index("interface Vlan10")


def test_acl_binding_is_translated_once_with_interface_context():
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
    svi = graph.by_feature("interface.svi")[0]
    binding = graph.by_feature("acl_binding")[0]

    assert "traffic-filter inbound acl 3000" not in "\n".join(svi.source_lines)
    assert binding.source_lines == ["traffic-filter inbound acl 3000"]

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")

    assert assembly.deployable_config.count("ip access-group 3000 in") == 1
    assert "interface Vlan10" in assembly.deployable_config


def test_cisco_acl_binding_module_translates_to_huawei_with_interface_context():
    config = """interface Vlan10
 ip address 10.0.10.1 255.255.255.0
 ip access-group WEB-IN in
#
ip access-list extended WEB-IN
 10 permit ip any any
"""
    graph = build_module_graph(config, vendor="cisco")
    svi = graph.by_feature("interface.svi")[0]
    binding = graph.by_feature("acl_binding")[0]

    assert "ip access-group WEB-IN in" not in "\n".join(svi.source_lines)
    assert binding.source_lines == ["ip access-group WEB-IN in"]

    assembly = translate_module_graph(graph, from_vendor="cisco", to_vendor="huawei")

    assert assembly.deployable_config.count("traffic-filter inbound acl WEB-IN") == 1
    assert "interface Vlanif10" in assembly.deployable_config


def test_h3c_acl_binding_module_translates_to_cisco_with_interface_context():
    config = """interface Vlan-interface10
 ip address 10.0.10.1 255.255.255.0
 packet-filter 3000 inbound
#
acl number 3000
 rule 5 permit ip
"""
    graph = build_module_graph(config, vendor="h3c")
    svi = graph.by_feature("interface.svi")[0]
    binding = graph.by_feature("acl_binding")[0]

    assert "packet-filter 3000 inbound" not in "\n".join(svi.source_lines)
    assert binding.source_lines == ["packet-filter 3000 inbound"]

    assembly = translate_module_graph(graph, from_vendor="h3c", to_vendor="cisco")

    assert assembly.deployable_config.count("ip access-group 3000 in") == 1
    assert "interface Vlan10" in assembly.deployable_config


def test_device_identity_is_separate_from_generic_system_module():
    graph = build_module_graph("sysname CORE-SW\nclock timezone CST add 08:00:00\n", vendor="huawei")

    identity = graph.by_feature("device_identity")[0]
    system = graph.by_feature("system")[0]

    assert "device:hostname" in identity.provides
    assert identity.source_lines == ["sysname CORE-SW"]
    assert system.source_lines == ["clock timezone CST add 08:00:00"]


def test_firewall_policy_uses_zone_address_and_service_objects():
    config = """security-zone name trust
#
security-zone name untrust
#
ip address-set WEB type object
 address 0 10.1.1.10 mask 255.255.255.255
#
ip service-set HTTP type object
 service 0 protocol tcp destination-port 80
#
security-policy
 rule name allow-web
  source-zone trust
  destination-zone untrust
  destination-address WEB
  service HTTP
  action permit
"""
    graph = build_module_graph(config, vendor="huawei_usg")

    policy = graph.by_feature("security_policy")[0]

    assert graph.by_feature("zone")
    assert graph.by_feature("address_object")
    assert graph.by_feature("service_object")
    assert {"zone:trust", "zone:untrust", "addr:WEB", "svc:HTTP"}.issubset(set(policy.consumes))
    assert any(coupling["relation"] == "policy_uses_object" for coupling in graph.to_dict()["couplings"])


def test_interface_kinds_are_split_into_specific_module_features():
    config = """interface LoopBack0
 ip address 10.0.0.1 255.255.255.255
#
interface Eth-Trunk1
 mode lacp-static
#
interface GigabitEthernet0/0/1
 eth-trunk 1
"""
    graph = build_module_graph(config, vendor="huawei")

    assert graph.by_feature("interface.loopback")
    assert graph.by_feature("interface.lag")
    assert graph.by_feature("interface.physical")
    physical = graph.by_feature("interface.physical")[0]
    lag = graph.by_feature("interface.lag")[0]
    assert "lag:1" in physical.consumes
    assert lag.module_id in physical.depends_on
    assert any(coupling["relation"] == "member_of_lag" for coupling in graph.to_dict()["couplings"])
