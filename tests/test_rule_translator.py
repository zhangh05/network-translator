from core.rule_translator import RuleBasedTranslator


def test_rule_translator_converts_cisco_acl_to_huawei_acl():
    result = RuleBasedTranslator().translate(
        """access-list 101 permit tcp 192.168.1.0 0.0.0.255 any eq 80
access-list 101 deny ip any any
""",
        from_vendor="cisco",
        to_vendor="huawei",
    )

    assert "```huawei" in result
    assert "acl number 101" in result
    assert "rule permit tcp source 192.168.1.0 0.0.0.255 destination any destination-port eq 80" in result
    assert "rule deny ip source any destination any" in result


def test_rule_translator_converts_cisco_bgp_to_huawei_bgp():
    result = RuleBasedTranslator().translate(
        """router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
 network 172.16.0.0 mask 255.255.0.0
""",
        from_vendor="cisco",
        to_vendor="huawei",
    )

    assert "bgp 65001" in result
    assert "peer 10.0.0.2 as-number 65002" in result
    assert "ipv4-family unicast" in result
    assert " network 172.16.0.0 255.255.0.0" in result


def test_rule_translator_converts_static_routes_and_trunks():
    result = RuleBasedTranslator().translate(
        """ip route 10.10.0.0 255.255.0.0 192.168.1.1
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk allowed vlan 10,20
""",
        from_vendor="cisco",
        to_vendor="huawei",
    )

    assert "ip route-static 10.10.0.0 255.255.0.0 192.168.1.1" in result
    assert "port link-type trunk" in result
    assert "port trunk allow-pass vlan 10 20" in result


def _executable_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith(("```", "!", "#"))
    ]


def test_rule_translator_converts_huawei_switch_primitives_to_cisco():
    result = RuleBasedTranslator().translate(
        """sysname HW-SW
vlan batch 10 20 101 to 102
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
interface Eth-Trunk1
 port link-type trunk
 port trunk allow-pass vlan 10 20 101 to 102
interface XGigabitEthernet0/0/1
 eth-trunk 1
ip route-static 0.0.0.0 0.0.0.0 10.0.10.254
""",
        from_vendor="huawei",
        to_vendor="cisco",
    )

    assert "hostname HW-SW" in result
    assert "vlan 10,20,101-102" in result
    assert "interface Vlan10" in result
    assert "ip address 10.0.10.1 255.255.255.0" in result
    assert "interface Port-channel1" in result
    assert "switchport mode trunk" in result
    assert "switchport trunk allowed vlan 10,20,101-102" in result
    assert "interface GigabitEthernet0/0/1" in result
    assert "channel-group 1 mode active" in result
    assert "ip route 0.0.0.0 0.0.0.0 10.0.10.254" in result


def test_rule_translator_converts_h3c_vlan_interface_to_cisco_vlan_interface():
    result = RuleBasedTranslator().translate(
        """sysname TEST
interface Vlan-interface30
 ip address 10.0.0.1 255.255.255.0
interface Bridge-Aggregation10
 port link-type trunk
 port trunk permit vlan 30 40
""",
        from_vendor="h3c",
        to_vendor="cisco",
    )

    assert "hostname TEST" in result
    assert "interface Vlan30" in result
    assert "interface Port-channel10" in result
    assert "switchport trunk allowed vlan 30,40" in result


def test_rule_translator_comments_unsupported_huawei_qos_in_cisco_output():
    result = RuleBasedTranslator().translate(
        """traffic classifier TC operator and
 if-match acl 3000
traffic behavior TB
 redirect ip-nexthop 10.0.0.1
traffic policy TP
 classifier TC behavior TB precedence 5
local-user admin password irreversible-cipher x
""",
        from_vendor="huawei",
        to_vendor="cisco",
    )
    executable = "\n".join(_executable_lines(result))

    assert "! MANUAL_REVIEW" in result
    assert "traffic classifier" not in executable
    assert "traffic behavior" not in executable
    assert "traffic policy" not in executable
    assert "local-user" not in executable


def test_rule_translator_converts_huawei_vrf_static_route_to_cisco():
    result = RuleBasedTranslator().translate(
        "ip route-static vpn-instance MGMT 10.10.0.0 255.255.0.0 192.168.1.1\n",
        from_vendor="huawei",
        to_vendor="cisco",
    )

    assert "ip route vrf MGMT 10.10.0.0 255.255.0.0 192.168.1.1" in result
    assert "ip route vpn-instance" not in result


def test_rule_translator_converts_huawei_named_acl_rules_to_cisco_extended_acl():
    result = RuleBasedTranslator().translate(
        """acl name D-ACL-JRZW 3985
 rule 5 deny ip source 140.19.1.0 0.0.0.255 destination 140.19.2.0 0.0.0.255
 rule 60 permit ip
""",
        from_vendor="huawei",
        to_vendor="cisco",
    )

    assert "ip access-list extended D-ACL-JRZW" in result
    assert "5 deny ip 140.19.1.0 0.0.0.255 140.19.2.0 0.0.0.255" in result
    assert "60 permit ip any any" in result


def test_rule_translator_converts_huawei_numbered_acl_source_only_rule_to_cisco():
    result = RuleBasedTranslator().translate(
        """acl number 2002
 rule 5 permit source 140.4.10.30 0
""",
        from_vendor="huawei",
        to_vendor="cisco",
    )

    assert "ip access-list extended 2002" in result
    assert "5 permit ip host 140.4.10.30 any" in result


def test_rule_translator_converts_huawei_secondary_ip_and_loopback_names_to_cisco():
    result = RuleBasedTranslator().translate(
        """interface LoopBack0
 ip address 10.0.0.1 255.255.255.255
interface Vlanif105
 ip address 140.19.0.2 255.255.255.224 sub
interface NULL0
""",
        from_vendor="huawei",
        to_vendor="cisco",
    )

    assert "interface Loopback0" in result
    assert "ip address 140.19.0.2 255.255.255.224 secondary" in result
    assert "interface Null0" in result
    assert " sub" not in "\n".join(_executable_lines(result))


def test_rule_translator_comments_unsupported_huawei_management_interface_children():
    result = RuleBasedTranslator().translate(
        """interface MEth0/0/1
 ip address 192.168.1.253 255.255.255.0
 description mgmt
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
""",
        from_vendor="huawei",
        to_vendor="cisco",
    )
    executable = "\n".join(_executable_lines(result))

    assert "! MANUAL_REVIEW unsupported source command: interface MEth0/0/1" in result
    assert "192.168.1.253" not in executable
    assert "description mgmt" not in executable
    assert "interface Vlan10" in executable
    assert "ip address 10.0.10.1 255.255.255.0" in executable
