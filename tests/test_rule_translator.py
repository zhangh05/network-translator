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
