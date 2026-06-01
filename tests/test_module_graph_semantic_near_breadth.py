# -*- coding: utf-8 -*-
"""Broad semantic-near coverage for complex module families.

These tests keep complex features out of deployable_config while giving users
usable target-shape suggestions in the semantic-near review view.
"""

import pytest

from core.module_graph import build_module_graph, translate_module_graph


def _result(config, feature, from_vendor="huawei", to_vendor="cisco"):
    graph = build_module_graph(config, vendor=from_vendor)
    assembly = translate_module_graph(graph, from_vendor=from_vendor, to_vendor=to_vendor)
    matches = [result for result in assembly.results if result.feature == feature]
    assert matches, f"missing result feature {feature}; got {[r.feature for r in assembly.results]}"
    return matches[0], assembly


@pytest.mark.parametrize(
    "feature,config,expected",
    [
        (
            "route_filter",
            "ip ip-prefix EXPORT index 10 permit 10.10.0.0 24\n",
            "ip prefix-list EXPORT",
        ),
        (
            "pbr.policy",
            "policy-based-route PBR permit node 10\n if-match acl 3000\n apply next-hop 10.0.0.1\n",
            "route-map PBR permit 10",
        ),
        (
            "pbr.binding",
            "interface Vlanif10\n ip policy-based-route PBR\n",
            "ip policy route-map PBR",
        ),
        (
            "object_group",
            "object-group network SRC\n network-object host 10.0.0.10\n",
            "object-group network SRC",
        ),
        (
            "object_group.member",
            "object-group network SRC\n network-object host 10.0.0.10\n",
            "host 10.0.0.10",
        ),
        (
            "time_range",
            "time-range WORK 08:00 to 18:00 working-day\n",
            "time-range WORK",
        ),
        (
            "acl.time_range",
            "acl number 3000\n rule 5 permit ip source any destination any time-range WORK\n",
            "time-range WORK",
        ),
        (
            "acl.object_group",
            "acl number 3000\n rule 5 permit ip source object-group SRC destination any\n",
            "object-group SRC",
        ),
    ],
)

def test_policy_filter_object_and_time_modules_are_semantic_near(feature, config, expected):
    result, assembly = _result(config, feature, from_vendor="huawei", to_vendor="cisco")

    assert result.status == "semantic_near"
    assert expected in "\n".join(result.suggested_lines)
    assert expected not in assembly.deployable_config
    assert result.manual_review_lines


@pytest.mark.parametrize(
    "feature,config,expected,to_vendor",
    [
        ("ipv6.static_route", "ipv6 route-static 2001:db8:10:: 64 2001:db8::1\n", "ipv6 route", "cisco"),
        ("ipv6.interface", "interface Vlanif10\n ipv6 enable\n ipv6 address 2001:db8:10::1/64\n", "ipv6 address", "cisco"),
        ("ipv6.nd_ra", "interface Vlanif10\n ipv6 nd ra halt\n ipv6 nd ra interval 30\n", "ipv6 nd", "cisco"),
        ("ipv6.acl", "ipv6 access-list V6-FILTER\n permit tcp any any eq 443\n", "ipv6 access-list V6-FILTER", "cisco"),
        ("ospfv3.process", "ospfv3 1\n router-id 1.1.1.1\n area 0\n", "ipv6 router ospf 1", "cisco"),
        ("ripng.process", "ripng 1\n import-route static\n", "ipv6 router rip", "cisco"),
        ("dhcpv6.pool", "ipv6 dhcp pool V6POOL\n address prefix 2001:db8:10::/64\n", "ipv6 dhcp pool V6POOL", "cisco"),
        ("dhcpv6.relay.binding", "interface Vlanif10\n ipv6 dhcp relay destination 2001:db8::10\n", "ipv6 dhcp relay destination 2001:db8::10", "cisco"),
    ],
)

def test_ipv6_and_next_gen_routing_modules_are_semantic_near(feature, config, expected, to_vendor):
    result, assembly = _result(config, feature, from_vendor="huawei", to_vendor=to_vendor)

    assert result.status == "semantic_near"
    assert expected in "\n".join(result.suggested_lines)
    assert expected not in assembly.deployable_config


@pytest.mark.parametrize(
    "feature,config,expected",
    [
        ("bfd.session", "bfd SESSION bind peer-ip 10.0.0.2 source-ip 10.0.0.1\n discriminator local 10\n discriminator remote 20\n", "bfd interval"),
        ("mpls.ldp", "mpls ldp\n lsr-id 1.1.1.1\n", "mpls ldp"),
        ("mpls.te", "mpls te\n tunnel mpls traffic-eng\n", "mpls traffic-eng"),
        ("mpls.l3vpn", "ip vpn-instance CUST-A\n ipv4-family\n  route-distinguisher 65000:1\n  vpn-target 65000:1 export-extcommunity\n", "vrf definition CUST-A"),
        ("segment_routing", "segment-routing\n mpls\n", "segment-routing"),
        ("segment_routing.binding", "isis 1\n segment-routing mpls\n", "segment-routing mpls"),
    ],
)

def test_reliability_mpls_and_segment_routing_modules_are_semantic_near(feature, config, expected):
    result, assembly = _result(config, feature, from_vendor="huawei", to_vendor="cisco")

    assert result.status == "semantic_near"
    assert expected in "\n".join(result.suggested_lines)
    if feature != "mpls.l3vpn":
        assert expected not in assembly.deployable_config


@pytest.mark.parametrize(
    "feature,config,expected",
    [
        ("firewall.nat", "nat-policy\n rule name NAT1\n  source-zone trust\n  action source-nat easy-ip\n", "nat policy NAT1"),
        ("firewall.ipsec", "ipsec policy VPN 10 isakmp\n security acl 3000\n remote-address 10.0.0.2\n ike proposal 10\n", "crypto map VPN"),
        ("firewall.profile", "url-filter profile WEB-FILTER\n category block gambling\n", "security profile WEB-FILTER"),
        ("firewall.ips", "ips profile IPS-PROFILE\n signature-set critical\n", "ips policy IPS-PROFILE"),
        ("firewall.ha", "hrp enable\n hrp interface GigabitEthernet0/0/1 remote 10.0.0.2\n", "redundancy"),
        ("firewall.vsys", "virtual-system vsys1\n assign interface GigabitEthernet0/0/2\n", "context vsys1"),
    ],
)

def test_firewall_advanced_modules_are_semantic_near(feature, config, expected):
    result, assembly = _result(config, feature, from_vendor="huawei_usg", to_vendor="cisco")

    assert result.status == "semantic_near"
    assert expected in "\n".join(result.suggested_lines)
    assert expected not in assembly.deployable_config


@pytest.mark.parametrize(
    "feature,config,expected",
    [
        ("l2.private_vlan", "private-vlan primary 100\n", "private-vlan"),
        ("l2.vlan_mapping", "vlan mapping 100 map-vlan 200\n", "vlan mapping"),
        ("l2.dhcp_snooping", "dhcp snooping enable\n", "ip dhcp snooping"),
        ("l2.source_guard", "ip source guard\n", "ip verify source"),
        ("l2.arp_security", "arp inspection enable\n", "ip arp inspection"),
        ("l2.port_security", "port-security enable\n", "switchport port-security"),
        ("l2.storm_control", "storm-control broadcast level 10\n", "storm-control"),
        ("monitor.span", "monitor session 1 source interface GigabitEthernet0/1\n", "monitor session 1"),
        ("oam.ethernet", "ethernet oam enable\n", "ethernet oam"),
        ("security.urpf", "interface GigabitEthernet0/0/1\n ip verify unicast reverse-path\n", "ip verify unicast source reachable-via"),
    ],
)

def test_l2_security_monitoring_and_oam_modules_are_semantic_near(feature, config, expected):
    result, assembly = _result(config, feature, from_vendor="huawei", to_vendor="cisco")

    assert result.status == "semantic_near"
    assert expected in "\n".join(result.suggested_lines)
    assert expected not in assembly.deployable_config

@pytest.mark.parametrize(
    "feature,config,expected,vendor,target",
    [
        ("platform.stack", "irf member 1 priority 32\n", "stackwise-virtual", "huawei", "cisco"),
        ("overlay.vxlan", "vxlan vni 10010\n source 10.0.0.1\n", "vxlan vni 10010", "huawei", "cisco"),
        ("overlay.evpn", "evpn\n route-distinguisher 65000:100\n vpn-target 65000:100 export-extcommunity\n", "l2vpn evpn", "huawei", "cisco"),
        ("nqa", "nqa test-instance admin icmp1\n test-type icmp\n destination-address ipv4 10.0.0.1\n", "ip sla", "huawei", "cisco"),
        ("ip_sla", "ip sla 10\n icmp-echo 10.0.0.1\n", "nqa test-instance", "cisco", "huawei"),
        ("eigrp", "router eigrp 100\n network 10.0.0.0\n", "router eigrp 100", "cisco", "huawei"),
        ("dhcp.pool", "ip pool USERS\n network 10.0.10.0 mask 255.255.255.0\n gateway-list 10.0.10.1\n dns-list 10.0.0.53\n", "ip dhcp pool USERS", "huawei", "cisco"),
        ("interface.tunnel", "interface Tunnel10\n ip address 10.0.0.1 255.255.255.252\n tunnel-protocol gre\n source 10.0.1.1\n destination 10.0.1.2\n", "interface Tunnel10", "huawei", "cisco"),
    ],
)

def test_platform_overlay_sla_eigrp_dhcp_and_tunnel_modules_are_semantic_near(feature, config, expected, vendor, target):
    result, assembly = _result(config, feature, from_vendor=vendor, to_vendor=target)

    assert result.status == "semantic_near"
    assert expected in "\n".join(result.suggested_lines)
    assert expected not in assembly.deployable_config


@pytest.mark.parametrize(
    "feature,config,expected",
    [
        ("management.ssh", "stelnet server enable\nssh user admin authentication-type password\n", "ip ssh version 2"),
        ("management.pki", "pki domain CORP\n certificate request entity ENT\n", "crypto pki trustpoint CORP"),
        ("management.aaa", "aaa\n local-user admin password cipher SECRET\n local-user admin privilege level 15\n", "aaa new-model"),
        ("management.ntp_auth", "ntp authentication-key 1 md5 SECRET\nntp-service reliable authentication-keyid 1\n", "ntp authentication-key 1 md5 <redacted>"),
        ("management.netconf", "netconf ssh server enable\n", "netconf-yang"),
        ("management.restconf", "restconf\n", "restconf"),
        ("management.telemetry", "telemetry\n sensor-group IF\n", "telemetry"),
        ("telemetry.flow", "ip flow-export destination 10.0.0.10 2055\n", "flow exporter"),
    ],
)

def test_management_and_telemetry_modules_are_semantic_near(feature, config, expected):
    result, assembly = _result(config, feature, from_vendor="huawei", to_vendor="cisco")

    assert result.status == "semantic_near"
    assert expected in "\n".join(result.suggested_lines)
    assert "SECRET" not in "\n".join(result.suggested_lines)
    assert expected not in assembly.deployable_config

@pytest.mark.parametrize(
    "feature,config,expected",
    [
        ("bgp.vpnv4", "bgp 65000\n ipv4-family vpnv4\n  peer 10.0.0.2 enable\n", "address-family vpnv4"),
        ("bgp.evpn", "bgp 65000\n l2vpn-family evpn\n  peer 10.0.0.2 enable\n", "address-family l2vpn evpn"),
        ("bgp.flowspec", "bgp 65000\n ipv4-family flow\n  peer 10.0.0.2 enable\n", "address-family ipv4 flowspec"),
        ("bgp.confederation", "bgp 65000\n confederation id 65001\n", "bgp confederation identifier 65001"),
        ("bgp.route_reflector", "bgp 65000\n peer 10.0.0.2 reflect-client\n", "neighbor 10.0.0.2 route-reflector-client"),
        ("bgp.max_prefix", "bgp 65000\n peer 10.0.0.2 route-limit 1000\n", "neighbor 10.0.0.2 maximum-prefix 1000"),
        ("bgp.gtsm", "bgp 65000\n peer 10.0.0.2 valid-ttl-hops 1\n", "neighbor 10.0.0.2 ttl-security hops 1"),
        ("bgp.graceful_restart", "bgp 65000\n graceful-restart\n", "bgp graceful-restart"),
    ],
)
def test_bgp_advanced_modules_are_semantic_near(feature, config, expected):
    result, assembly = _result(config, feature, from_vendor="huawei", to_vendor="cisco")

    assert result.status == "semantic_near"
    assert expected in "\n".join(result.suggested_lines)
    assert expected not in assembly.deployable_config

@pytest.mark.parametrize(
    "feature,config,expected",
    [
        ("ipv6.nd_snooping", "ipv6 nd snooping enable\n", "ipv6 nd inspection"),
        ("ipv6.source_guard", "ipv6 source guard\n", "ipv6 verify source"),
        ("ipv6.ra_guard", "ipv6 ra guard policy RAGUARD\n", "ipv6 nd raguard policy RAGUARD"),
        ("pbr.track", "pbr track TRACK1\n", "track TRACK1"),
        ("pbr.verify", "pbr verify-availability enable\n", "verify-availability"),
        ("ospf.te", "ospf 1\n mpls traffic-eng area 0\n", "mpls traffic-eng area 0"),
        ("multicast.msdp", "msdp\n peer 10.0.0.2 connect-interface LoopBack0\n", "ip msdp peer 10.0.0.2"),
        ("fhrp.track", "interface Vlanif10\n vrrp vrid 1 track interface GigabitEthernet0/0/1 reduced 30\n", "standby 1 track GigabitEthernet0/0/1 decrement 30"),
    ],
)
def test_remaining_router_control_modules_are_semantic_near(feature, config, expected):
    result, assembly = _result(config, feature, from_vendor="huawei", to_vendor="cisco")

    assert result.status == "semantic_near"
    assert expected in "\n".join(result.suggested_lines)
    assert expected not in assembly.deployable_config


@pytest.mark.parametrize(
    "feature,config,expected",
    [
        ("l2.ring_protection", "erps ring 1\n control-vlan 4094\n", "ethernet ring-protection"),
        ("l2.smart_link", "smart-link group 1\n protected-vlan reference-instance 1\n", "smart-link group 1"),
        ("l2.mlag", "m-lag 1\n peer-link Eth-Trunk10\n", "mlag domain 1"),
        ("l2.gvrp", "gvrp\n", "gvrp"),
        ("l2.mvrp", "mvrp enable\n", "mvrp"),
        ("l2.device_tracking", "ip device tracking\n", "device-tracking policy"),
        ("l2.errdisable", "errdisable recovery cause bpduguard\n", "errdisable recovery cause bpduguard"),
        ("monitor.rspan", "remote-probe vlan 999\n", "monitor session <id> source remote vlan 999"),
        ("oam.cfm", "cfm md MD1 level 3\n", "ethernet cfm"),
    ],
)
def test_remaining_switch_oam_resilience_modules_are_semantic_near(feature, config, expected):
    result, assembly = _result(config, feature, from_vendor="huawei", to_vendor="cisco")

    assert result.status == "semantic_near"
    assert expected in "\n".join(result.suggested_lines)
    assert expected not in assembly.deployable_config


@pytest.mark.parametrize(
    "feature,config,expected",
    [
        ("firewall.ssl_vpn", "ssl vpn gateway SSLVPN\n ip address 10.0.0.1 port 443\n", "ssl vpn gateway SSLVPN"),
        ("firewall.dos", "dos-policy\n rule name anti-flood\n", "dos profile"),
        ("firewall.dlp", "dlp profile DLP-PROFILE\n file-type block exe\n", "dlp profile DLP-PROFILE"),
        ("firewall.waf", "waf profile WAF-PROFILE\n signature enable\n", "waf profile WAF-PROFILE"),
        ("firewall.load_balance", "load-balance virtual-server VS-WEB\n real-server RS1 10.0.0.10\n", "load-balance virtual-server VS-WEB"),
        ("firewall.proxy", "proxy-policy\n rule name web-proxy\n", "proxy policy"),
        ("firewall.decryption", "decryption-policy\n rule name ssl-decrypt\n", "ssl decryption policy"),
        ("firewall.routing", "firewall routing-instance VRF1\n", "firewall routing-instance VRF1"),
    ],
)
def test_remaining_firewall_service_modules_are_semantic_near(feature, config, expected):
    result, assembly = _result(config, feature, from_vendor="huawei_usg", to_vendor="cisco")

    assert result.status == "semantic_near"
    assert expected in "\n".join(result.suggested_lines)
    assert expected not in assembly.deployable_config
