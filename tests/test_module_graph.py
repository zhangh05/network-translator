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
    assert graph.by_feature("ospf.process")
    assert graph.by_feature("ospf.network")
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
    ospf_module = graph.by_feature("ospf.process")[0]
    network_module = graph.by_feature("ospf.network")[0]

    assert "ospf:1" in ospf_module.provides
    assert ospf_module.source_lines[0].startswith("ospf 1")
    assert "ospf:1" in network_module.consumes
    assert any("network 10.0.10.0" in line for line in network_module.source_lines)


def test_vendor_specific_unknown_feature_becomes_manual_review_module():
    graph = build_module_graph(SAMPLE_CONFIG, vendor="huawei")
    review_modules = graph.manual_review_modules()

    assert any("voice-vlan" in "\n".join(module.source_lines) for module in review_modules)
    assert any(module.feature == "l2.voice_vlan" for module in review_modules)
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
    assert module_summary["ospf.process"] == 1
    assert module_summary["ospf.area"] == 1
    assert module_summary["ospf.network"] == 1
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
    assert any(item.status in {"manual_review", "semantic_near"} for item in assembly.results)


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


def test_ospf_submodules_keep_authentication_and_redistribute_out_of_deployable():
    config = """ospf 1 router-id 10.0.0.1
 area 0.0.0.0
  network 10.0.10.0 0.0.0.255
 silent-interface Vlanif10
 area 0.0.0.0 authentication-mode md5
 import-route static
"""
    graph = build_module_graph(config, vendor="huawei")

    assert graph.by_feature("ospf.process")
    assert graph.by_feature("ospf.area")
    assert graph.by_feature("ospf.network")
    assert graph.by_feature("ospf.passive_interface")
    assert graph.by_feature("ospf.authentication")[0].status == "manual_review"
    assert graph.by_feature("ospf.redistribute")[0].status == "manual_review"

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")

    assert "router ospf 1" in assembly.deployable_config
    assert "network 10.0.10.0 0.0.0.255" in assembly.deployable_config
    assert "passive-interface Vlanif10" in assembly.deployable_config
    assert "authentication-mode" not in assembly.deployable_config
    assert "import-route static" not in assembly.deployable_config
    assert "authentication-mode md5" in assembly.manual_review_config
    assert "import-route static" in assembly.manual_review_config


def test_cisco_ospf_authentication_and_redistribute_are_manual_review_submodules():
    config = """router ospf 1
 router-id 10.0.0.1
 network 10.0.10.0 0.0.0.255 area 0
 passive-interface Vlan10
 redistribute static
 area 0 authentication message-digest
"""
    graph = build_module_graph(config, vendor="cisco")

    assert graph.by_feature("ospf.process")
    assert graph.by_feature("ospf.network")
    assert graph.by_feature("ospf.passive_interface")
    assert graph.by_feature("ospf.authentication")[0].status == "manual_review"
    assert graph.by_feature("ospf.redistribute")[0].status == "manual_review"

    assembly = translate_module_graph(graph, from_vendor="cisco", to_vendor="huawei")

    assert "ospf 1" in assembly.deployable_config
    assert "network 10.0.10.0 0.0.0.255 area 0" in assembly.deployable_config
    assert "silent-interface Vlan10" in assembly.deployable_config
    assert "redistribute static" not in assembly.deployable_config
    assert "authentication message-digest" not in assembly.deployable_config
    assert "redistribute static" in assembly.manual_review_config
    assert "authentication message-digest" in assembly.manual_review_config


def test_bgp_submodules_keep_password_and_policy_out_of_deployable():
    config = """bgp 65000
 router-id 10.0.0.1
 peer 10.0.0.2 as-number 65001
 peer 10.0.0.2 password cipher SECRET_KEY
 peer 10.0.0.2 route-policy EXPORT export
 network 10.10.0.0 255.255.255.0
 import-route static
"""
    graph = build_module_graph(config, vendor="huawei")

    assert graph.by_feature("bgp.process")
    assert graph.by_feature("bgp.neighbor")
    assert graph.by_feature("bgp.network")
    assert graph.by_feature("bgp.password")[0].status == "manual_review"
    assert graph.by_feature("bgp.policy")[0].status == "manual_review"
    assert graph.by_feature("bgp.redistribute")[0].status == "manual_review"

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")

    assert "router bgp 65000" in assembly.deployable_config
    assert "neighbor 10.0.0.2 remote-as 65001" in assembly.deployable_config
    assert "network 10.10.0.0" in assembly.deployable_config
    assert "SECRET_KEY" not in assembly.deployable_config
    assert "route-policy EXPORT" not in assembly.deployable_config
    assert "import-route static" not in assembly.deployable_config
    assert "SECRET_KEY" not in assembly.manual_review_config
    assert "<redacted>" in assembly.manual_review_config
    assert "route-policy EXPORT export" in assembly.manual_review_config
    assert "import-route static" in assembly.manual_review_config


def test_cisco_bgp_submodules_keep_password_and_route_map_out_of_deployable():
    config = """router bgp 65000
 bgp router-id 10.0.0.1
 neighbor 10.0.0.2 remote-as 65001
 neighbor 10.0.0.2 password SECRET_KEY
 neighbor 10.0.0.2 route-map EXPORT out
 network 10.10.0.0 mask 255.255.255.0
 redistribute connected
"""
    graph = build_module_graph(config, vendor="cisco")

    assert graph.by_feature("bgp.process")
    assert graph.by_feature("bgp.neighbor")
    assert graph.by_feature("bgp.network")
    assert graph.by_feature("bgp.password")[0].status == "manual_review"
    assert graph.by_feature("bgp.policy")[0].status == "manual_review"
    assert graph.by_feature("bgp.redistribute")[0].status == "manual_review"

    assembly = translate_module_graph(graph, from_vendor="cisco", to_vendor="huawei")

    assert "bgp 65000" in assembly.deployable_config
    assert "peer 10.0.0.2 as-number 65001" in assembly.deployable_config
    assert "network 10.10.0.0 255.255.255.0" in assembly.deployable_config
    assert "SECRET_KEY" not in assembly.deployable_config
    assert "route-map EXPORT" not in assembly.deployable_config
    assert "redistribute connected" not in assembly.deployable_config
    assert "SECRET_KEY" not in assembly.manual_review_config
    assert "<redacted>" in assembly.manual_review_config
    assert "route-map EXPORT out" in assembly.manual_review_config
    assert "redistribute connected" in assembly.manual_review_config


def test_static_route_modules_track_vrf_dependency_and_risky_options():
    config = """ip vpn-instance CUST-A
 ipv4-family
  route-distinguisher 65000:1
#
ip route-static 0.0.0.0 0.0.0.0 10.0.0.1
ip route-static vpn-instance CUST-A 10.10.0.0 255.255.255.0 10.0.0.2
ip route-static 10.20.0.0 255.255.255.0 10.0.0.3 track 1 tag 200
"""
    graph = build_module_graph(config, vendor="huawei")

    vrf = graph.by_feature("vrf")[0]
    routes = graph.by_feature("static_route")
    risky = graph.by_feature("static_route.option")[0]

    assert "vrf:CUST-A" in vrf.provides
    assert len(routes) == 2
    assert any("vrf:CUST-A" in route.consumes for route in routes)
    assert risky.status == "manual_review"
    assert "track 1 tag 200" in "\n".join(risky.source_lines)
    assert any(coupling["relation"] == "route_uses_vrf" for coupling in graph.to_dict()["couplings"])

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")

    assert "ip route 0.0.0.0 0.0.0.0 10.0.0.1" in assembly.deployable_config
    assert "track 1 tag 200" not in assembly.deployable_config
    assert "track 1 tag 200" in assembly.manual_review_config


def test_route_policy_module_links_acl_and_stays_manual_review():
    config = """acl number 3000
 rule 5 permit ip
#
route-policy EXPORT permit node 10
 if-match acl 3000
 apply local-preference 200
"""
    graph = build_module_graph(config, vendor="huawei")

    acl = graph.by_feature("acl")[0]
    policy = graph.by_feature("route_policy")[0]

    assert "route-policy:EXPORT" in policy.provides
    assert "acl:3000" in policy.consumes
    assert policy.status == "manual_review"
    assert acl.module_id in policy.depends_on
    assert any(coupling["relation"] == "policy_uses_acl" for coupling in graph.to_dict()["couplings"])

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")

    assert "route-policy EXPORT" not in assembly.deployable_config
    assert "route-policy EXPORT" in assembly.manual_review_config


def test_qos_modules_link_classifier_behavior_policy_and_acl():
    config = """acl number 3000
 rule 5 permit ip
#
traffic classifier C1
 if-match acl 3000
#
traffic behavior B1
 remark dscp af31
#
traffic policy P1
 classifier C1 behavior B1
"""
    graph = build_module_graph(config, vendor="huawei")

    classifier = graph.by_feature("qos.classifier")[0]
    behavior = graph.by_feature("qos.behavior")[0]
    policy = graph.by_feature("qos.policy")[0]

    assert "qos-classifier:C1" in classifier.provides
    assert "acl:3000" in classifier.consumes
    assert "qos-behavior:B1" in behavior.provides
    assert {"qos-classifier:C1", "qos-behavior:B1"}.issubset(set(policy.consumes))
    assert policy.status == "manual_review"
    assert any(coupling["relation"] == "qos_policy_uses_part" for coupling in graph.to_dict()["couplings"])


def test_management_modules_split_ntp_snmp_and_redact_snmp_secret():
    config = """ntp-service unicast-server 10.0.0.1
snmp-agent community read cipher SECRET_COMMUNITY
info-center loghost 10.0.0.2
"""
    graph = build_module_graph(config, vendor="huawei")

    assert graph.by_feature("management.ntp")[0].status == "translatable"
    snmp = graph.by_feature("management.snmp")[0]
    logging = graph.by_feature("management.logging")[0]

    assert snmp.status == "manual_review"
    assert "SECRET_COMMUNITY" not in "\n".join(snmp.source_lines)
    assert "<redacted>" in "\n".join(snmp.source_lines)
    assert logging.status == "translatable"

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")

    assert "ntp server 10.0.0.1" in assembly.deployable_config
    assert "SECRET_COMMUNITY" not in assembly.manual_review_config
    assert "<redacted>" in assembly.manual_review_config


def test_bfd_module_extracts_session_and_stays_manual_review():
    config = """bfd SESSION1 bind peer-ip 10.0.0.2 source-ip 10.0.0.1
 discriminator local 1
 discriminator remote 2
"""
    graph = build_module_graph(config, vendor="huawei")

    bfd = graph.by_feature("bfd.session")[0]

    assert bfd.status == "manual_review"
    assert "bfd:SESSION1" in bfd.provides
    assert "peer:10.0.0.2" in bfd.consumes
    assert "source:10.0.0.1" in bfd.consumes
    assert "bfd session" in bfd.manual_review_reason.lower()


def test_vrrp_is_split_from_interface_and_kept_manual_review_with_interface_dependency():
    config = """vlan batch 10
#
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
 vrrp vrid 1 virtual-ip 10.0.10.254
 vrrp vrid 1 priority 120
"""
    graph = build_module_graph(config, vendor="huawei")

    svi = graph.by_feature("interface.svi")[0]
    vrrp = graph.by_feature("fhrp.vrrp")[0]

    assert "vrrp vrid" not in "\n".join(svi.source_lines)
    assert vrrp.status == "manual_review"
    assert "interface:Vlanif10" in vrrp.consumes
    assert "vrrp:Vlanif10:1" in vrrp.provides
    assert svi.module_id in vrrp.depends_on
    assert any(coupling["relation"] == "fhrp_uses_interface" for coupling in graph.to_dict()["couplings"])

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")

    assert "vrrp vrid" not in assembly.deployable_config
    assert "vrrp vrid 1 virtual-ip 10.0.10.254" in assembly.manual_review_config


def test_dhcp_pool_module_extracts_pool_and_gateway():
    config = """ip pool LAN
 network 10.0.10.0 mask 255.255.255.0
 gateway-list 10.0.10.1
 dns-list 10.0.0.53
"""
    graph = build_module_graph(config, vendor="huawei")

    dhcp = graph.by_feature("dhcp.pool")[0]

    assert dhcp.status == "manual_review"
    assert "dhcp-pool:LAN" in dhcp.provides
    assert "subnet:10.0.10.0/255.255.255.0" in dhcp.provides
    assert "gateway:10.0.10.1" in dhcp.consumes


def test_tunnel_module_extracts_endpoints_and_stays_manual_review_for_gre():
    config = """interface Tunnel0/0/0
 tunnel-protocol gre
 source 10.0.0.1
 destination 10.0.0.2
 ip address 172.16.0.1 255.255.255.252
"""
    graph = build_module_graph(config, vendor="huawei")

    tunnel = graph.by_feature("interface.tunnel")[0]

    assert tunnel.status == "manual_review"
    assert "tunnel: Tunnel0/0/0" not in tunnel.provides
    assert "tunnel:Tunnel0/0/0" in tunnel.provides
    assert "source:10.0.0.1" in tunnel.consumes
    assert "destination:10.0.0.2" in tunnel.consumes
    assert "gre" in tunnel.tags


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


def test_firewall_policy_uses_time_range_and_security_profiles():
    config = """time-range WORK
 period-range 08:00 to 18:00 working-day
#
url-filter profile WEB-FILTER
 category block gambling
#
antivirus profile AV-STRICT
 scan enable
#
security-policy
 rule name allow-web
  source-zone trust
  destination-zone untrust
  service HTTP
  time-range WORK
  profile WEB-FILTER
  antivirus profile AV-STRICT
  action permit
"""
    graph = build_module_graph(config, vendor="huawei_usg")

    policy = graph.by_feature("security_policy")[0]
    time_range = graph.by_feature("time_range")[0]
    profiles = graph.by_feature("firewall.profile")

    assert "time-range:WORK" in policy.consumes
    assert {"profile:WEB-FILTER", "profile:AV-STRICT"}.issubset(set(policy.consumes))
    assert time_range.module_id in policy.depends_on
    assert {profile.module_id for profile in profiles}.issubset(set(policy.depends_on))
    couplings = graph.to_dict()["couplings"]
    assert any(coupling["relation"] == "policy_uses_time_range" for coupling in couplings)
    assert any(coupling["relation"] == "policy_uses_profile" for coupling in couplings)


def test_inline_firewall_policy_uses_schedule_and_profile_refs():
    config = """time-range WORK
 periodic weekdays 08:00 to 18:00
#
url-filter profile WEB-FILTER
#
policy p1 from trust to untrust source SRC destination DST service HTTP schedule WORK profile WEB-FILTER action permit
"""
    graph = build_module_graph(config, vendor="hillstone")

    policy = graph.by_feature("security_policy")[0]

    assert "time-range:WORK" in policy.consumes
    assert "profile:WEB-FILTER" in policy.consumes
    assert any(coupling["relation"] == "policy_uses_time_range" for coupling in graph.to_dict()["couplings"])
    assert any(coupling["relation"] == "policy_uses_profile" for coupling in graph.to_dict()["couplings"])


def test_acl_uses_time_range_and_object_group_refs():
    config = """time-range WORK
 periodic weekdays 08:00 to 18:00
#
object-group network WEB-SERVERS
 network-object host 10.1.1.10
#
ip access-list extended WEB-IN
 permit tcp object-group WEB-SERVERS any eq 443 time-range WORK
"""
    graph = build_module_graph(config, vendor="cisco")

    acl = graph.by_feature("acl")[0]
    time_range = graph.by_feature("time_range")[0]
    object_group = graph.by_feature("object_group")[0]

    assert "time-range:WORK" in acl.consumes
    assert "object-group:WEB-SERVERS" in acl.consumes
    assert time_range.module_id in acl.depends_on
    assert object_group.module_id in acl.depends_on
    assert any(coupling["relation"] == "acl_uses_time_range" for coupling in graph.to_dict()["couplings"])
    assert any(coupling["relation"] == "acl_uses_object_group" for coupling in graph.to_dict()["couplings"])


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


def test_rip_block_is_split_into_process_network_and_redistribute_review_modules():
    config = """router rip
 version 2
 network 10.0.0.0
 redistribute static
"""
    graph = build_module_graph(config, vendor="cisco")

    assert graph.by_feature("rip.process")
    assert graph.by_feature("rip.network")
    assert graph.by_feature("rip.redistribute")[0].status == "manual_review"
    assert "rip:default" in graph.by_feature("rip.process")[0].provides
    assert "rip:default" in graph.by_feature("rip.network")[0].consumes


def test_isis_block_is_typed_manual_review_with_network_entity():
    config = """isis 1
 network-entity 49.0001.0000.0000.0001.00
 cost-style wide
 import-route static
"""
    graph = build_module_graph(config, vendor="huawei")

    process = graph.by_feature("isis.process")[0]
    net = graph.by_feature("isis.network_entity")[0]
    tuning = graph.by_feature("isis.interface_tuning")[0]
    redistribute = graph.by_feature("isis.redistribute")[0]

    assert process.status == "manual_review"
    assert "isis:1" in process.provides
    assert "isis:1" in net.consumes
    assert tuning.status == "manual_review"
    assert redistribute.status == "manual_review"


def test_pbr_policy_and_interface_binding_are_split_with_route_policy_dependency():
    config = """route-map PBR permit 10
 match ip address 3000
 set ip next-hop 10.0.0.254
#
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.0
 ip policy route-map PBR
"""
    graph = build_module_graph(config, vendor="cisco")

    interface = graph.by_feature("interface.physical")[0]
    binding = graph.by_feature("pbr.binding")[0]

    assert "ip policy route-map" not in "\n".join(interface.source_lines)
    assert binding.status == "manual_review"
    assert "interface:GigabitEthernet0/0/1" in binding.consumes
    assert "route-policy:PBR" in binding.consumes
    assert any(coupling["relation"] == "pbr_uses_policy" for coupling in graph.to_dict()["couplings"])


def test_multicast_interface_lines_are_split_from_interface_and_reviewed():
    config = """interface GigabitEthernet0/0/2
 ip address 10.0.20.1 255.255.255.0
 ip pim sparse-mode
 igmp enable
"""
    graph = build_module_graph(config, vendor="cisco")

    interface = graph.by_feature("interface.physical")[0]
    multicast = graph.by_feature("multicast.interface")[0]

    assert "pim" not in "\n".join(interface.source_lines).lower()
    assert multicast.status == "manual_review"
    assert "interface:GigabitEthernet0/0/2" in multicast.consumes
    assert "pim" in multicast.tags
    assert "igmp" in multicast.tags


def test_firewall_nat_policy_is_typed_manual_review_with_zone_refs():
    config = """security-zone name trust
#
security-zone name untrust
#
nat-policy
 rule name srcnat
  source-zone trust
  destination-zone untrust
  action source-nat easy-ip
"""
    graph = build_module_graph(config, vendor="huawei_usg")

    nat = graph.by_feature("firewall.nat")[0]

    assert nat.status == "manual_review"
    assert "zone:trust" in nat.consumes
    assert "zone:untrust" in nat.consumes
    assert "nat-policy:srcnat" in nat.provides
    assert any(coupling["relation"] == "nat_uses_object" for coupling in graph.to_dict()["couplings"])


def test_ipsec_and_ike_blocks_are_typed_manual_review_with_secret_redaction():
    config = """ike proposal 10
 encryption-algorithm aes-cbc-256
#
ike peer VPN-PEER
 pre-shared-key cipher SECRET_KEY
 remote-address 10.0.0.2
#
ipsec policy VPN 1 isakmp
 security acl 3000
 ike-peer VPN-PEER
 proposal TRANS
"""
    graph = build_module_graph(config, vendor="huawei_usg")

    modules = graph.by_feature("firewall.ipsec")
    joined = "\n".join(line for module in modules for line in module.source_lines)

    assert len(modules) == 3
    assert all(module.status == "manual_review" for module in modules)
    assert "SECRET_KEY" not in joined
    assert "<redacted>" in joined
    assert any("acl:3000" in module.consumes for module in modules)
    assert any("ipsec-policy:VPN:1" in module.provides for module in modules)


def test_firewall_profile_and_time_range_are_typed_manual_review_modules():
    config = """time-range WORK
 period-range 08:00 to 18:00 working-day
#
url-filter profile WEB-FILTER
 category block gambling
#
antivirus profile AV-STRICT
 scan enable
"""
    graph = build_module_graph(config, vendor="topsec")

    time_range = graph.by_feature("time_range")[0]
    profiles = graph.by_feature("firewall.profile")

    assert time_range.status == "manual_review"
    assert "time-range:WORK" in time_range.provides
    assert len(profiles) == 2
    assert {"profile:WEB-FILTER", "profile:AV-STRICT"}.issubset({item for module in profiles for item in module.provides})
    assert all(module.status == "manual_review" for module in profiles)


def test_interface_qos_binding_links_policy_to_interface():
    config = """traffic classifier WEB
 if-match acl 3000
#
traffic behavior LIMIT
 car cir 10240
#
traffic policy EDGE-QOS
 classifier WEB behavior LIMIT
#
interface GigabitEthernet0/0/1
 traffic-policy EDGE-QOS inbound
"""
    graph = build_module_graph(config, vendor="huawei")

    binding = graph.by_feature("qos.binding")[0]
    policy = graph.by_feature("qos.policy")[0]
    interface = graph.by_feature("interface.physical")[0]

    assert binding.status == "translatable"
    assert {"interface:GigabitEthernet0/0/1", "qos-policy:EDGE-QOS"}.issubset(set(binding.consumes))
    assert policy.module_id in binding.depends_on
    assert interface.module_id in binding.depends_on
    assert any(coupling["relation"] == "binds_qos_to_interface" for coupling in graph.to_dict()["couplings"])
    assert not any("traffic-policy EDGE-QOS inbound" in line for line in interface.source_lines)


def test_cisco_service_policy_binding_links_policy_to_interface():
    config = """policy-map WAN-QOS
 class class-default
  police 1000000
#
interface GigabitEthernet0/1
 service-policy input WAN-QOS
"""
    graph = build_module_graph(config, vendor="cisco")

    binding = graph.by_feature("qos.binding")[0]

    assert binding.status == "translatable"
    assert {"interface:GigabitEthernet0/1", "qos-policy:WAN-QOS"}.issubset(set(binding.consumes))
    assert "inbound" in binding.tags
    assert any(coupling["relation"] == "binds_qos_to_interface" for coupling in graph.to_dict()["couplings"])


def test_qos_binding_is_deployable_but_policy_body_is_semantic_near():
    config = """traffic classifier WEB
 if-match acl 3000
#
traffic behavior SETDSCP
 remark dscp 46
#
traffic policy SETDSCP
 classifier WEB behavior SETDSCP
#
interface Vlanif105
 traffic-policy SETDSCP outbound
"""
    graph = build_module_graph(config, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")
    by_feature = {result.feature: result for result in assembly.results}

    assert "service-policy output SETDSCP" in assembly.deployable_config
    assert "traffic classifier WEB" not in assembly.deployable_config

    assert by_feature["qos.binding"].status == "translated"
    assert by_feature["qos.policy"].status == "semantic_near"
    assert by_feature["qos.policy"].suggested_lines
    assert "policy-map SETDSCP" in "\n".join(by_feature["qos.policy"].suggested_lines)
    assert assembly.coverage["semantic_near_modules"] >= 1


def test_bgp_policy_line_links_to_route_policy_provider():
    config = """route-policy EXPORT permit node 10
 if-match acl 3000
 apply local-preference 200
#
bgp 65000
 peer 10.0.0.2 as-number 65001
 peer 10.0.0.2 route-policy EXPORT export
"""
    graph = build_module_graph(config, vendor="huawei")

    route_policy = graph.by_feature("route_policy")[0]
    bgp_policy = graph.by_feature("bgp.policy")[0]

    assert "route-policy:EXPORT" in route_policy.provides
    assert "route-policy:EXPORT" in bgp_policy.consumes
    assert route_policy.module_id in bgp_policy.depends_on
    assert any(coupling["relation"] == "bgp_uses_route_policy" for coupling in graph.to_dict()["couplings"])


def test_cisco_bgp_route_map_line_links_to_route_policy_provider():
    config = """route-map EXPORT permit 10
 match ip address 3000
 set local-preference 200
#
router bgp 65000
 neighbor 10.0.0.2 remote-as 65001
 neighbor 10.0.0.2 route-map EXPORT out
"""
    graph = build_module_graph(config, vendor="cisco")

    bgp_policy = graph.by_feature("bgp.policy")[0]

    assert "route-policy:EXPORT" in bgp_policy.consumes
    assert any(coupling["relation"] == "bgp_uses_route_policy" for coupling in graph.to_dict()["couplings"])


def test_route_policy_links_to_prefix_filter_provider():
    config = """ip ip-prefix EXPORT index 10 permit 10.0.0.0 24
#
route-policy EXPORT permit node 10
 if-match ip-prefix EXPORT
 apply local-preference 200
"""
    graph = build_module_graph(config, vendor="huawei")

    route_filter = graph.by_feature("route_filter")[0]
    route_policy = graph.by_feature("route_policy")[0]

    assert "route-filter:EXPORT" in route_filter.provides
    assert "route-filter:EXPORT" in route_policy.consumes
    assert route_filter.module_id in route_policy.depends_on
    assert any(coupling["relation"] == "policy_uses_route_filter" for coupling in graph.to_dict()["couplings"])


def test_cisco_route_map_links_to_prefix_list_provider():
    config = """ip prefix-list EXPORT seq 10 permit 10.0.0.0/24
#
route-map EXPORT permit 10
 match ip address prefix-list EXPORT
 set local-preference 200
"""
    graph = build_module_graph(config, vendor="cisco")

    route_filter = graph.by_feature("route_filter")[0]
    route_policy = graph.by_feature("route_policy")[0]

    assert "route-filter:EXPORT" in route_filter.provides
    assert "route-filter:EXPORT" in route_policy.consumes
    assert route_filter.module_id in route_policy.depends_on


def test_bgp_direct_prefix_filter_links_to_route_filter_provider():
    config = """ip ip-prefix EXPORT index 10 permit 10.0.0.0 24
#
bgp 65000
 peer 10.0.0.2 as-number 65001
 peer 10.0.0.2 ip-prefix EXPORT export
"""
    graph = build_module_graph(config, vendor="huawei")

    bgp_policy = graph.by_feature("bgp.policy")[0]
    route_filter = graph.by_feature("route_filter")[0]

    assert "route-filter:EXPORT" in bgp_policy.consumes
    assert route_filter.module_id in bgp_policy.depends_on
    assert any(coupling["relation"] == "bgp_uses_route_filter" for coupling in graph.to_dict()["couplings"])


def test_network_object_group_members_are_split_for_review():
    config = """object-group network WEB-SERVERS
 network-object host 10.1.1.10
 network-object 10.1.2.0 255.255.255.0
"""
    graph = build_module_graph(config, vendor="cisco")

    parent = graph.by_feature("object_group")[0]
    members = graph.by_feature("object_group.member")

    assert parent.status == "manual_review"
    assert "object-group:WEB-SERVERS" in parent.provides
    assert parent.source_lines == ["object-group network WEB-SERVERS"]
    assert len(members) == 2
    assert all(member.status == "manual_review" for member in members)
    assert all("object-group:WEB-SERVERS" in member.consumes for member in members)
    assert parent.module_id in members[0].depends_on
    assert any(coupling["relation"] == "object_group_has_member" for coupling in graph.to_dict()["couplings"])


def test_service_object_group_members_are_split_for_review():
    config = """object-group service WEB-SVC
 service-object tcp destination eq 443
 port-object eq 80
"""
    graph = build_module_graph(config, vendor="cisco")

    parent = graph.by_feature("object_group")[0]
    members = graph.by_feature("object_group.member")

    assert "service" in parent.tags
    assert len(members) == 2
    assert all("service" in member.tags for member in members)
    assert all("object-group:WEB-SVC" in member.consumes for member in members)


def test_module_translation_assembly_reports_complete_coverage():
    graph = build_module_graph(SAMPLE_CONFIG, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")
    payload = assembly.to_dict()
    coverage = payload["coverage"]

    assert coverage["total_modules"] == len(graph.modules)
    assert coverage["result_modules"] == len(graph.modules)
    assert coverage["missing_module_ids"] == []
    assert coverage["translated_modules"] > 0
    assert coverage["manual_review_modules"] + coverage["semantic_near_modules"] > 0
    assert coverage["all_modules_accounted"] is True


def test_regular_fallback_uses_module_translation_contract():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "timeout")
    state.set("config_text", SAMPLE_CONFIG)

    FallbackNode().execute(state)

    assert state.get("fallback_used") is True
    assert state.get("module_graph", {}).get("modules")
    assert state.get("module_translations", {}).get("results")
    assert state.get("module_translation_coverage", {}).get("all_modules_accounted") is True
    assert "voice-vlan" in state.get("manual_review_config", "")
    assert "voice-vlan" not in state.get("deployable_config", "")


def test_cache_hit_preserves_module_translation_contract():
    class ValidLLM:
        model = "test-model"

        def chat(self, *args, **kwargs):
            return {
                "content": (
                    '[{"type":"system","original_lines":["sysname HW-SW"],'
                    '"translated_lines":["hostname HW-SW"],"notes":"","confidence":1.0},'
                    '{"type":"vlan","original_lines":["vlan batch 10"],'
                    '"translated_lines":["vlan 10"],"notes":"","confidence":1.0}]'
                )
            }

    cache_dir = tempfile.mkdtemp()
    agent = GraphAgent(
        llm=ValidLLM(),
        cache_dir=cache_dir,
        memory_dir=tempfile.mkdtemp(),
    )
    config = "sysname HW-SW\nvlan batch 10\n"

    first = agent.run(config, from_vendor="huawei", to_vendor="cisco")
    second = agent.run(config, from_vendor="huawei", to_vendor="cisco")

    assert first["cache_hit"] is False
    assert second["cache_hit"] is True
    assert second["module_graph"]["modules"]
    assert second["module_translations"]["results"]
    assert second["module_translation_coverage"]["all_modules_accounted"] is True


def test_access_authentication_profile_is_split_as_manual_review_module():
    config = """authentication-profile name dot1x_authen_profile
 dot1x-access-profile dot1x_access
 mac-access-profile mac_access
 access-domain corp force
"""
    graph = build_module_graph(config, vendor="huawei")
    module = graph.by_feature("access.auth_profile")[0]

    assert module.status == "manual_review"
    assert "auth-profile:dot1x_authen_profile" in module.provides
    assert "domain:corp" in module.consumes
    assert "dot1x" in module.tags
    assert "mac-auth" in module.tags
    assert "准入认证" in module.manual_review_reason


def test_access_interface_binding_links_interface_to_auth_profile():
    config = """authentication-profile name dot1x_authen_profile
 dot1x-access-profile dot1x_access
#
interface GigabitEthernet0/0/1
 port link-type access
 port default vlan 10
 authentication-profile dot1x_authen_profile
 dot1x enable
 mac-authentication enable
"""
    graph = build_module_graph(config, vendor="huawei")
    binding = graph.by_feature("access.interface_binding")[0]

    assert binding.status == "manual_review"
    assert "interface:GigabitEthernet0/0/1" in binding.consumes
    assert "auth-profile:dot1x_authen_profile" in binding.consumes
    assert "dot1x" in binding.tags
    assert "mac-auth" in binding.tags
    assert binding.depends_on
    assert any(c["relation"] == "access_binding_uses_auth_profile" for c in graph.to_dict()["couplings"])


def test_cisco_access_session_and_mab_are_access_interface_binding_modules():
    config = """interface GigabitEthernet1/0/10
 switchport mode access
 authentication port-control auto
 authentication event fail action next-method
 mab
 dot1x pae authenticator
 access-session host-mode multi-auth
"""
    graph = build_module_graph(config, vendor="cisco")
    binding = graph.by_feature("access.interface_binding")[0]

    assert binding.status == "manual_review"
    assert "interface:GigabitEthernet1/0/10" in binding.consumes
    assert {"dot1x", "mab", "fail-policy"}.issubset(set(binding.tags))
    assert "authentication event fail" in "\n".join(binding.source_lines)


def test_access_portal_and_radius_domain_modules_are_manual_review():
    config = """portal server PORTAL ip 10.10.10.10 url http://portal.example.local
#
radius scheme RAD1
 primary authentication 10.10.10.20
 key authentication cipher RadiusKey
#
domain corp
 authentication lan-access radius-scheme RAD1
 authorization lan-access radius-scheme RAD1
 accounting lan-access radius-scheme RAD1
"""
    graph = build_module_graph(config, vendor="h3c")
    features = {module.feature for module in graph.modules}
    radius_modules = graph.by_feature("access.radius_binding")
    domain_binding = next(module for module in radius_modules if "domain:corp" in module.provides)

    assert "access.portal" in features
    assert "access.radius_binding" in features
    assert all(module.status == "manual_review" for module in radius_modules)
    assert "radius-scheme:RAD1" in domain_binding.consumes
    assert "RadiusKey" not in "\n".join(line for module in radius_modules for line in module.source_lines)


def test_route_policy_body_is_semantic_near_not_deployable():
    config = """ip ip-prefix EXPORT index 10 permit 10.0.0.0 24
#
route-policy EXPORT permit node 10
 if-match ip-prefix EXPORT
 apply local-preference 200
"""
    graph = build_module_graph(config, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")
    route_policy = next(result for result in assembly.results if result.feature == "route_policy")

    assert route_policy.status == "semantic_near"
    assert route_policy.suggested_lines
    assert "route-map EXPORT permit 10" in "\n".join(route_policy.suggested_lines)
    assert "match ip address prefix-list EXPORT" in "\n".join(route_policy.suggested_lines)
    assert "set local-preference 200" in "\n".join(route_policy.suggested_lines)
    assert "route-map EXPORT" not in assembly.deployable_config
    assert "route-policy EXPORT" in assembly.manual_review_config


def test_bgp_policy_reference_is_semantic_near_with_target_neighbor_shape():
    config = """route-policy EXPORT permit node 10
 if-match acl 3000
#
bgp 65000
 peer 10.0.0.2 as-number 65001
 peer 10.0.0.2 route-policy EXPORT export
"""
    graph = build_module_graph(config, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")
    bgp_policy = next(result for result in assembly.results if result.feature == "bgp.policy")

    assert bgp_policy.status == "semantic_near"
    assert "neighbor 10.0.0.2 route-map EXPORT out" in "\n".join(bgp_policy.suggested_lines)
    assert "route-policy EXPORT export" not in assembly.deployable_config
    assert "route-policy EXPORT export" in assembly.manual_review_config


def test_fhrp_vrrp_is_semantic_near_with_hsrp_skeleton():
    config = """vlan batch 10
#
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
 vrrp vrid 1 virtual-ip 10.0.10.254
 vrrp vrid 1 priority 120
 vrrp vrid 1 preempt-mode timer delay 30
"""
    graph = build_module_graph(config, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")
    fhrp = next(result for result in assembly.results if result.feature == "fhrp.vrrp")

    assert fhrp.status == "semantic_near"
    suggested = "\n".join(fhrp.suggested_lines)
    assert "interface Vlan10" in suggested
    assert "standby 1 ip 10.0.10.254" in suggested
    assert "standby 1 priority 120" in suggested
    assert "vrrp vrid" not in assembly.deployable_config
    assert "vrrp vrid 1 virtual-ip 10.0.10.254" in assembly.manual_review_config


def test_dhcp_relay_binding_is_semantic_near_with_helper_address_suggestion():
    config = """interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
 dhcp select relay
 dhcp relay server-ip 10.0.0.10
"""
    graph = build_module_graph(config, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")
    relay = next(result for result in assembly.results if result.feature == "dhcp.relay.binding")

    assert relay.status == "semantic_near"
    assert "ip helper-address 10.0.0.10" in "\n".join(relay.suggested_lines)
    assert "dhcp relay" not in assembly.deployable_config
    assert "dhcp relay server-ip 10.0.0.10" in assembly.manual_review_config


def test_management_snmp_is_semantic_near_and_redacted():
    config = """snmp-agent community read cipher SECRET_COMMUNITY
snmp-agent sys-info contact noc@example.invalid
"""
    graph = build_module_graph(config, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")
    snmp = next(result for result in assembly.results if result.feature == "management.snmp")

    assert snmp.status == "semantic_near"
    suggested = "\n".join(snmp.suggested_lines)
    assert "snmp-server community <redacted> RO" in suggested
    assert "SECRET_COMMUNITY" not in suggested
    assert "SECRET_COMMUNITY" not in assembly.manual_review_config
    assert "snmp-server community" not in assembly.deployable_config


def test_static_route_option_is_semantic_near_with_base_route_suggestion():
    config = """ip route-static 10.20.0.0 255.255.255.0 10.0.0.3 track 1 tag 200 description WAN
"""
    graph = build_module_graph(config, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")
    route = next(result for result in assembly.results if result.feature == "static_route.option")

    assert route.status == "semantic_near"
    assert "ip route 10.20.0.0 255.255.255.0 10.0.0.3" in "\n".join(route.suggested_lines)
    assert "track 1" not in assembly.deployable_config
    assert "track 1 tag 200" in assembly.manual_review_config


def test_lacp_tuning_is_semantic_near_with_timer_suggestion():
    config = """interface Eth-Trunk10
 lacp timeout fast
 lacp preempt enable
"""
    graph = build_module_graph(config, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")
    lacp = next(result for result in assembly.results if result.feature == "lacp.tuning")

    assert lacp.status == "semantic_near"
    suggested = "\n".join(lacp.suggested_lines)
    assert "lacp rate fast" in suggested
    assert "confirm LACP preempt" in suggested
    assert "lacp timeout fast" not in assembly.deployable_config


def test_mstp_region_is_semantic_near_with_mst_configuration_suggestion():
    config = """stp region-configuration
 region-name CORE
 revision-level 1
 instance 1 vlan 10 20
 active region-configuration
"""
    graph = build_module_graph(config, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")
    mstp = next(result for result in assembly.results if result.feature == "stp.mstp")

    assert mstp.status == "semantic_near"
    suggested = "\n".join(mstp.suggested_lines)
    assert "spanning-tree mst configuration" in suggested
    assert "name CORE" in suggested
    assert "instance 1 vlan 10 20" in suggested
    assert "stp region-configuration" not in assembly.deployable_config


def test_ospf_redistribute_and_authentication_are_semantic_near_suggestions():
    config = """ospf 1
 area 0.0.0.0
  authentication-mode md5 1 cipher SECRET_OSPF
  network 10.0.10.0 0.0.0.255
 import-route static
"""
    graph = build_module_graph(config, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")
    auth = next(result for result in assembly.results if result.feature == "ospf.authentication")
    redist = next(result for result in assembly.results if result.feature == "ospf.redistribute")

    assert auth.status == "semantic_near"
    assert redist.status == "semantic_near"
    assert "area 0 authentication message-digest" in "\n".join(auth.suggested_lines)
    assert "redistribute static" in "\n".join(redist.suggested_lines)
    assert "SECRET_OSPF" not in "\n".join(auth.suggested_lines)
    assert "authentication-mode md5" not in assembly.deployable_config
    assert "import-route static" not in assembly.deployable_config


def test_rip_process_network_and_redistribute_are_semantic_near():
    config = """router rip
 version 2
 network 10.0.0.0
 redistribute static
"""
    graph = build_module_graph(config, vendor="cisco")

    assembly = translate_module_graph(graph, from_vendor="cisco", to_vendor="huawei")
    by_feature = {result.feature: result for result in assembly.results}

    assert by_feature["rip.process"].status == "semantic_near"
    assert by_feature["rip.network"].status == "semantic_near"
    assert by_feature["rip.redistribute"].status == "semantic_near"
    assert "rip 1" in "\n".join(by_feature["rip.process"].suggested_lines)
    assert "network 10.0.0.0" in "\n".join(by_feature["rip.network"].suggested_lines)
    assert "import-route static" in "\n".join(by_feature["rip.redistribute"].suggested_lines)
    assert "router rip" not in assembly.deployable_config


def test_isis_process_net_and_redistribute_are_semantic_near():
    config = """isis 1
 network-entity 49.0001.0000.0000.0001.00
 cost-style wide
 import-route static
"""
    graph = build_module_graph(config, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")
    by_feature = {result.feature: result for result in assembly.results}

    assert by_feature["isis.process"].status == "semantic_near"
    assert by_feature["isis.network_entity"].status == "semantic_near"
    assert by_feature["isis.interface_tuning"].status == "semantic_near"
    assert by_feature["isis.redistribute"].status == "semantic_near"
    assert "router isis 1" in "\n".join(by_feature["isis.process"].suggested_lines)
    assert "net 49.0001.0000.0000.0001.00" in "\n".join(by_feature["isis.network_entity"].suggested_lines)
    assert "metric-style wide" in "\n".join(by_feature["isis.interface_tuning"].suggested_lines)
    assert "redistribute static" in "\n".join(by_feature["isis.redistribute"].suggested_lines)
    assert "network-entity" not in assembly.deployable_config


def test_multicast_rp_and_interface_are_semantic_near_suggestions():
    config = """pim rp-address 10.0.0.1
#
interface GigabitEthernet0/0/2
 ip address 10.0.20.1 255.255.255.0
 ip pim sparse-mode
 ip igmp version 2
"""
    graph = build_module_graph(config, vendor="cisco")

    assembly = translate_module_graph(graph, from_vendor="cisco", to_vendor="huawei")
    rp = next(result for result in assembly.results if result.feature == "multicast.rp")
    interface = next(result for result in assembly.results if result.feature == "multicast.interface")

    assert rp.status == "semantic_near"
    assert interface.status == "semantic_near"
    assert "multicast routing-enable" in "\n".join(rp.suggested_lines)
    assert "pim sm" in "\n".join(interface.suggested_lines)
    assert "igmp enable" in "\n".join(interface.suggested_lines)
    assert "ip pim sparse-mode" not in assembly.deployable_config


def test_access_auth_profile_and_interface_binding_are_semantic_near_suggestions():
    config = """authentication-profile name dot1x_authen_profile
 dot1x-access-profile dot1x_access
 mac-access-profile mac_access
 access-domain corp force
#
interface GigabitEthernet0/0/1
 port link-type access
 authentication-profile dot1x_authen_profile
 dot1x enable
 mac-authentication enable
"""
    graph = build_module_graph(config, vendor="huawei")

    assembly = translate_module_graph(graph, from_vendor="huawei", to_vendor="cisco")
    profile = next(result for result in assembly.results if result.feature == "access.auth_profile")
    binding = next(result for result in assembly.results if result.feature == "access.interface_binding")

    assert profile.status == "semantic_near"
    assert binding.status == "semantic_near"
    assert "aaa authentication dot1x" in "\n".join(profile.suggested_lines)
    assert "interface GigabitEthernet0/0/1" in "\n".join(binding.suggested_lines)
    assert "authentication port-control auto" in "\n".join(binding.suggested_lines)
    assert "authentication-profile" not in assembly.deployable_config
