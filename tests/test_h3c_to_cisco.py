# -*- coding: utf-8 -*-
"""Comprehensive tests for H3C→Cisco translation."""

from core.h3c_to_cisco import H3CToCiscoTranslator, detect_h3c_residue
from core.rule_translator import RuleBasedTranslator
from core.cisco_output_validator import CiscoOutputValidator


def _translate(text: str) -> str:
    return H3CToCiscoTranslator().translate_plain(text)


# ═══════════════════════════════════════════════════════════════
# 1. SVI: Vlan-interface → Vlan
# ═══════════════════════════════════════════════════════════════

def test_svi_vlan_interface_to_vlan():
    result = _translate("""interface Vlan-interface30
 description JK-B1
 ip address 10.55.6.252 255.255.255.0
 vrrp vrid 30 virtual-ip 10.55.6.254
 vrrp vrid 30 priority 90
""")
    assert "interface Vlan30" in result, f"Expected 'interface Vlan30' in:\n{result}"
    assert "description JK-B1" in result
    assert "ip address 10.55.6.252 255.255.255.0" in result
    assert "vrrp 30 ip 10.55.6.254" in result
    assert "vrrp 30 priority 90" in result


def test_svi_packet_filter_inbound():
    result = _translate("""interface Vlan-interface107
 description YW-6F
 ip address 10.52.7.252 255.255.255.0
 vrrp vrid 107 virtual-ip 10.52.7.254
 packet-filter 3050 inbound
""")
    assert "interface Vlan107" in result
    assert "ip access-group 3050 in" in result, f"Expected ip access-group 3050 in:\n{result}"


def test_svi_ospf_network_type():
    result = _translate("""interface Vlan-interface1000
 description TO-CORE
 ip address 10.54.1.17 255.255.255.248
 ospf network-type p2p
""")
    assert "interface Vlan1000" in result
    assert "ip ospf network point-to-point" in result


def test_svi_no_vrrp():
    result = _translate("""interface Vlan-interface1000
 description TO-CORE
 ip address 10.54.1.17 255.255.255.248
""")
    assert "interface Vlan1000" in result
    assert "Vlan-interface" not in result


# ═══════════════════════════════════════════════════════════════
# 2. VRRP: vrrp vrid → vrrp
# ═══════════════════════════════════════════════════════════════

def test_vrrp_translation():
    result = _translate("""interface Vlan-interface30
 vrrp vrid 30 virtual-ip 10.55.6.254
 vrrp vrid 30 priority 90
""")
    assert "vrrp 30 ip 10.55.6.254" in result
    assert "vrrp 30 priority 90" in result


def test_vrrp_multiple_ids():
    result = _translate("""interface Vlan-interface104
 vrrp vrid 104 virtual-ip 10.52.4.254
 vrrp vrid 104 priority 110
""")
    assert "vrrp 104 ip 10.52.4.254" in result


# ═══════════════════════════════════════════════════════════════
# 3. OSPF: silent-interface → passive-interface
# ═══════════════════════════════════════════════════════════════

def test_ospf_silent_all():
    result = _translate("""ospf 1 router-id 10.52.0.202
 import-route static
 silent-interface all
 undo silent-interface Vlan-interface1000
 undo silent-interface Vlan-interface1001
 area 0.0.0.0
  network 10.52.0.202 0.0.0.0
  network 10.52.4.0 0.0.0.255
""")
    assert "router ospf 1" in result
    assert "router-id 10.52.0.202" in result
    assert "redistribute static" in result, f"Expected redistribute static, got:\n{result}"
    assert "passive-interface default" in result
    assert "no passive-interface Vlan1000" in result
    assert "no passive-interface Vlan1001" in result
    assert "network 10.52.0.202 0.0.0.0 area 0" in result
    assert "network 10.52.4.0 0.0.0.255 area 0" in result


def test_ospf_network_areas():
    result = _translate("""ospf 1 router-id 10.52.0.202
 area 0.0.0.0
  network 10.52.0.202 0.0.0.0
  network 10.52.4.0 0.0.0.255
""")
    assert "network 10.52.0.202 0.0.0.0 area 0" in result
    assert "network 10.52.4.0 0.0.0.255 area 0" in result


def test_ospf_silent_interface_without_all():
    result = _translate("""ospf 1 router-id 10.52.0.202
 silent-interface Vlan-interface1000
 undo silent-interface Vlan-interface1001
""")
    assert "passive-interface Vlan1000" in result
    assert "no passive-interface Vlan1001" in result


# ═══════════════════════════════════════════════════════════════
# 4. Bridge-Aggregation → Port-channel
# ═══════════════════════════════════════════════════════════════

def test_bridge_aggregation_to_port_channel():
    result = _translate("""interface Bridge-Aggregation1
 description TO-CORE
 port link-type trunk
 port trunk permit vlan 1 30 to 40 104 to 154 205 to 254 1000 1002
""")
    assert "interface Port-channel1" in result
    assert "switchport mode trunk" in result
    assert "switchport trunk allowed vlan 1,30-40,104-154,205-254,1000,1002" in result
    assert "Bridge-Aggregation" not in result


def test_bridge_aggregation_dynamic():
    result = _translate("""interface Bridge-Aggregation100
 port link-type trunk
 port trunk permit vlan all
 link-aggregation mode dynamic
""")
    assert "interface Port-channel100" in result
    assert "switchport trunk allowed vlan all" in result
    assert "link-aggregation mode dynamic" not in result


# ═══════════════════════════════════════════════════════════════
# 5. port link-aggregation group → channel-group
# ═══════════════════════════════════════════════════════════════

def test_port_link_aggregation_group():
    result = _translate("""interface GigabitEthernet0/0/23
 description TO-CORE
 port link-type trunk
 port trunk permit vlan 1 30 to 40 104 to 154 205 to 254 1000 1002
 port link-aggregation group 1
""")
    assert "channel-group 1 mode active" in result


def test_multiple_member_ports():
    result = _translate("""interface GigabitEthernet0/0/23
 port link-aggregation group 1
""")
    assert "channel-group 1 mode active" in result


# ═══════════════════════════════════════════════════════════════
# 6. Trunk / Access VLAN
# ═══════════════════════════════════════════════════════════════

def test_trunk_vlan_convert():
    result = _translate("""interface GigabitEthernet0/0/7
 port link-type trunk
 port trunk permit vlan 1 30 to 34
""")
    assert "switchport mode trunk" in result
    assert "switchport trunk allowed vlan 1,30-34" in result


def test_trunk_vlan_all():
    result = _translate("""interface GigabitEthernet0/0/9
 port link-type trunk
 port trunk permit vlan all
""")
    assert "switchport trunk allowed vlan all" in result


def test_access_vlan():
    result = _translate("""interface GigabitEthernet0/0/5
 port access vlan 1001
""")
    assert "switchport mode access" in result
    assert "switchport access vlan 1001" in result


# ═══════════════════════════════════════════════════════════════
# 7. ACL: acl number → ip access-list extended
# ═══════════════════════════════════════════════════════════════

def test_acl_basic():
    result = _translate("""acl number 3050
 rule 0 permit ip source 10.54.7.181 0 destination 10.2.129.28 0
""")
    assert "ip access-list extended 3050" in result
    assert "permit ip host 10.54.7.181 host 10.2.129.28" in result


def test_acl_with_wildcard():
    result = _translate("""acl number 2000
 rule 10 permit source 10.5.0.0 0.0.255.255
 rule 20 permit source 20.5.0.0 0.0.255.255
""")
    assert "ip access-list standard 2000" in result, f"Expected standard ACL, got:\n{result}"
    assert "permit 10.5.0.0 0.0.255.255" in result
    assert "permit 20.5.0.0 0.0.255.255" in result


def test_acl_permit_ip_any():
    result = _translate("""acl number 3050
 rule 375 permit ip
""")
    assert "ip access-list extended 3050" in result
    assert "permit ip any any" in result


def test_acl_multiple_rules():
    result = _translate("""acl number 3050
 rule 0 permit ip source 10.54.7.181 0 destination 10.2.129.28 0
 rule 5 permit ip source 10.54.7.181 0 destination 10.3.129.28 0
 rule 375 permit ip
""")
    assert "permit ip host 10.54.7.181 host 10.2.129.28" in result
    assert "permit ip host 10.54.7.181 host 10.3.129.28" in result
    assert "permit ip any any" in result


# ═══════════════════════════════════════════════════════════════
# 8. packet-filter inbound → ip access-group in
# ═══════════════════════════════════════════════════════════════

def test_packet_filter_to_access_group():
    result = _translate("""interface Vlan-interface107
 packet-filter 3050 inbound
""")
    assert "ip access-group 3050 in" in result
    assert "packet-filter" not in result


# ═══════════════════════════════════════════════════════════════
# 9. ip route-static → ip route (CIDR/mask conversion)
# ═══════════════════════════════════════════════════════════════

def test_static_route_cidr():
    result = _translate("ip route-static 10.53.0.0 16 10.54.1.62")
    assert "ip route 10.53.0.0 255.255.0.0 10.54.1.62" in result


def test_static_route_mask():
    result = _translate("ip route-static 10.53.0.0 255.255.0.0 10.54.1.62")
    assert "ip route 10.53.0.0 255.255.0.0 10.54.1.62" in result


def test_static_route_31():
    result = _translate("ip route-static 172.18.22.180 31 10.54.1.62")
    assert "ip route 172.18.22.180 255.255.255.254 10.54.1.62" in result


def test_static_route_32():
    result = _translate("ip route-static 172.27.27.180 32 10.54.1.62")
    assert "ip route 172.27.27.180 255.255.255.255 10.54.1.62" in result


# ═══════════════════════════════════════════════════════════════
# 10. SNMP / NTP / SSH / LLDP
# ═══════════════════════════════════════════════════════════════

def test_snmp_community():
    result = _translate("snmp-agent community read zjtlcb acl 2000")
    assert "snmp-server community zjtlcb RO 2000" in result


def test_ntp():
    result = _translate("ntp-service unicast-server 20.5.101.10")
    assert "ntp server 20.5.101.10" in result


def test_ssh():
    result = _translate("ssh server enable")
    assert "ip ssh version 2" in result


def test_lldp():
    result = _translate("lldp global enable")
    assert "lldp run" in result


# ═══════════════════════════════════════════════════════════════
# 11. port link-mode bridge removal
# ═══════════════════════════════════════════════════════════════

def test_port_link_mode_bridge_removed():
    result = _translate("""interface GigabitEthernet0/0/1
 port link-mode bridge
 description test
""")
    assert "port link-mode" not in result
    assert "description test" in result


# ═══════════════════════════════════════════════════════════════
# 12. sysname → hostname
# ═══════════════════════════════════════════════════════════════

def test_sysname_to_hostname():
    result = _translate("sysname ZJQZ1TL2F_COR_CS7503E_01")
    assert "hostname ZJQZ1TL2F_COR_CS7503E_01" in result


# ═══════════════════════════════════════════════════════════════
# 13. Forbidden H3C token detector
# ═══════════════════════════════════════════════════════════════

def test_detect_h3c_residue():
    bad_config = """!
interface Vlan-interface30
 description test
 packet-filter 3050 inbound
!
"""
    residues = detect_h3c_residue(bad_config)
    tokens = {r["token"] for r in residues}
    assert "Vlan-interface" in tokens, f"Expected Vlan-interface in residues, got {tokens}"
    assert "packet-filter" in tokens, f"Expected packet-filter in residues, got {tokens}"


def test_no_residue_in_clean_cisco():
    clean_config = """hostname test
interface Vlan30
 description test
 ip access-group 3050 in
"""
    residues = detect_h3c_residue(clean_config)
    assert len(residues) == 0, f"Expected no residues, got {residues}"


# ═══════════════════════════════════════════════════════════════
# 14. Complete translation: no H3C residue in output
# ═══════════════════════════════════════════════════════════════

def test_full_config_no_h3c_residue():
    h3c_config = """sysname TEST-SWITCH
#
vlan 30
 name JK-B1
#
interface Vlan-interface30
 description JK-B1
 ip address 10.55.6.252 255.255.255.0
 vrrp vrid 30 virtual-ip 10.55.6.254
 vrrp vrid 30 priority 90
#
interface GigabitEthernet0/0/1
 port link-mode bridge
 description TO-CORE
 port link-type trunk
 port trunk permit vlan 1 30 to 40
#
ip route-static 10.53.0.0 16 10.54.1.62
#
acl number 3050
 rule 0 permit ip source 10.54.7.181 0 destination 10.2.129.28 0
#
return
"""
    result = _translate(h3c_config)
    residues = detect_h3c_residue(result)
    assert len(residues) == 0, f"H3C residues found in output:\n{result}\nResidues: {residues}"


# ═══════════════════════════════════════════════════════════════
# 15. CiscoOutputValidator tests
# ═══════════════════════════════════════════════════════════════

def test_validator_detects_residue():
    source = "interface Vlan-interface30"
    target = "interface Vlan-interface30"
    report = CiscoOutputValidator().validate(source, target)
    has_residue = any(i.category == "residue" for i in report.issues)
    assert has_residue, "Validator should detect Vlan-interface residue"
    assert not report.deployable, "Should not be deployable with residue"


def test_validator_passes_clean():
    source = "interface Vlan-interface30"
    target = "interface Vlan30"
    report = CiscoOutputValidator().validate(source, target)
    errors = [i for i in report.issues if i.severity == "error"]
    assert len(errors) == 0, f"Unexpected errors: {errors}"


def test_validator_detects_svi_mismatch():
    source = """interface Vlan-interface30
 ip address 10.0.0.1 255.255.255.0
interface Vlan-interface31
 ip address 10.0.1.1 255.255.255.0
interface Vlan-interface32
 ip address 10.0.2.1 255.255.255.0
"""
    target = """interface Vlan30
 ip address 10.0.0.1 255.255.255.0
interface Vlan32
 ip address 10.0.2.1 255.255.255.0
"""
    report = CiscoOutputValidator().validate(source, target)
    svi_issues = [i for i in report.issues if "SVI" in i.message and i.severity == "error"]
    assert len(svi_issues) > 0, "Validator should detect missing SVI 31"


def test_validator_detects_static_route_mismatch():
    source = """ip route-static 10.53.0.0 16 10.54.1.62
ip route-static 172.18.22.180 31 10.54.1.62
ip route-static 172.27.27.180 32 10.54.1.62
"""
    target = """ip route 10.53.0.0 255.255.0.0 10.54.1.62
"""
    report = CiscoOutputValidator().validate(source, target)
    route_issues = [i for i in report.issues if "静态路由" in i.message]
    assert len(route_issues) > 0, "Validator should detect missing static routes"


def test_validator_detects_acls_mismatch():
    source = """acl number 3050
 rule 0 permit ip source 10.54.7.181 0 destination 10.2.129.28 0
 rule 5 permit ip source 10.54.7.181 0 destination 10.3.129.28 0
 rule 375 permit ip
"""
    target = """ip access-list extended 3050
 permit ip host 10.54.7.181 host 10.2.129.28
"""
    report = CiscoOutputValidator().validate(source, target)
    acl_issues = [i for i in report.issues if "ACL" in i.message or "条目" in i.message]
    assert len(acl_issues) > 0, "Validator should detect missing ACL rules"


def test_validator_detects_packet_filter_migration():
    source = """interface Vlan-interface107
 packet-filter 3050 inbound
"""
    target = """interface Vlan107
"""
    report = CiscoOutputValidator().validate(source, target)
    pf_issues = [i for i in report.issues if "packet-filter" in i.message]
    assert len(pf_issues) > 0, "Validator should detect missing packet-filter migration"


def test_validator_detects_lag_migration():
    source = """interface GigabitEthernet0/0/23
 port link-aggregation group 1
"""
    target = """interface GigabitEthernet0/0/23
"""
    report = CiscoOutputValidator().validate(source, target)
    lag_issues = [i for i in report.issues if "port link-aggregation" in i.message]
    assert len(lag_issues) > 0, "Validator should detect missing link-aggregation migration"


# ═══════════════════════════════════════════════════════════════
# 16. RuleBasedTranslator line-level enhancements
# ═══════════════════════════════════════════════════════════════

def test_rule_translator_basic():
    result = RuleBasedTranslator().translate(
        "sysname TEST\ninterface Vlan-interface30\n ip address 10.0.0.1 255.255.255.0\n",
        from_vendor="h3c", to_vendor="cisco",
    )
    assert "hostname TEST" in result
    assert "interface Vlan30" in result


# ═══════════════════════════════════════════════════════════════
# 17. test_config.txt complete translation test
# ═══════════════════════════════════════════════════════════════

def test_complete_test_config_no_residue():
    """Test with the actual test_config.txt from the project."""
    import os
    config_path = "/Users/zhangh01/Desktop/codex_net_trans/_local/test_config.txt"
    if not os.path.exists(config_path):
        return  # skip if file not found
    with open(config_path) as f:
        h3c_config = f.read()
    result = _translate(h3c_config)
    residues = detect_h3c_residue(result)
    assert len(residues) == 0, f"H3C residues found in translated output:\n" + \
        "\n".join(f"  - {r['token']}: {r['context'][:60]}" for r in residues[:20])
    # Validate
    report = CiscoOutputValidator().validate(h3c_config, result)
    assert report.summary["errors"] == 0, \
        f"Validation errors: {[i.message for i in report.issues if i.severity == 'error']}"
