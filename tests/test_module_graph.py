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
