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
