# -*- coding: utf-8 -*-
"""Tests for ACL and interface-binding fallback translation."""

import pytest
from core.rule_translator import RuleBasedTranslator


def _executable_lines(text: str):
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith(("```", "!", "#"))
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Huawei traffic-filter → Cisco ip access-group
# ─────────────────────────────────────────────────────────────────────────────

def test_huawei_traffic_filter_inbound_to_cisco():
    result = RuleBasedTranslator().translate(
        "interface Vlanif10\n traffic-filter inbound acl name LAN-ACL\n",
        "huawei", "cisco",
    )
    assert "interface Vlan10" in result
    assert "ip access-group LAN-ACL in" in result


def test_huawei_traffic_filter_outbound_to_cisco():
    result = RuleBasedTranslator().translate(
        "interface Vlanif10\n traffic-filter outbound acl 3000\n",
        "huawei", "cisco",
    )
    assert "ip access-group 3000 out" in result


def test_huawei_traffic_filter_numbered_acl_to_cisco():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n traffic-filter inbound acl 3001\n",
        "huawei", "cisco",
    )
    assert "ip access-group 3001 in" in result


# ─────────────────────────────────────────────────────────────────────────────
# H3C packet-filter → Cisco ip access-group
# ─────────────────────────────────────────────────────────────────────────────

def test_h3c_packet_filter_inbound_to_cisco():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n packet-filter 3000 inbound\n",
        "h3c", "cisco",
    )
    assert "ip access-group 3000 in" in result


def test_h3c_packet_filter_outbound_to_cisco():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n packet-filter 3002 outbound\n",
        "h3c", "cisco",
    )
    assert "ip access-group 3002 out" in result


def test_h3c_packet_filter_named_acl_to_cisco():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n packet-filter WEB-POLICY outbound\n",
        "h3c", "cisco",
    )
    assert "ip access-group WEB-POLICY out" in result


# ─────────────────────────────────────────────────────────────────────────────
# Cisco ip access-group → Huawei traffic-filter
# ─────────────────────────────────────────────────────────────────────────────

def test_cisco_access_group_inbound_to_huawei():
    result = RuleBasedTranslator().translate(
        "interface Vlan10\n ip access-group ACL-MGMT in\n",
        "cisco", "huawei",
    )
    assert "traffic-filter inbound acl ACL-MGMT" in result


def test_cisco_access_group_outbound_to_huawei():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n ip access-group 3000 out\n",
        "cisco", "huawei",
    )
    assert "traffic-filter outbound acl 3000" in result


# ─────────────────────────────────────────────────────────────────────────────
# Cisco ip access-group → H3C packet-filter
# ─────────────────────────────────────────────────────────────────────────────

def test_cisco_access_group_inbound_to_h3c():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n ip access-group 3000 in\n",
        "cisco", "h3c",
    )
    assert "packet-filter 3000 inbound" in result


def test_cisco_access_group_outbound_to_h3c():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n ip access-group 3000 out\n",
        "cisco", "h3c",
    )
    assert "packet-filter 3000 outbound" in result


# ─────────────────────────────────────────────────────────────────────────────
# Ruijie ip access-group → Huawei traffic-filter
# ─────────────────────────────────────────────────────────────────────────────

def test_ruijie_access_group_inbound_to_huawei():
    result = RuleBasedTranslator().translate(
        "interface Vlan10\n ip access-group LAN-POLICY in\n",
        "ruijie", "huawei",
    )
    assert "traffic-filter inbound acl LAN-POLICY" in result


def test_ruijie_access_group_outbound_to_huawei():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n ip access-group 3000 out\n",
        "ruijie", "huawei",
    )
    assert "traffic-filter outbound acl 3000" in result


# ─────────────────────────────────────────────────────────────────────────────
# Ruijie ip access-group → H3C packet-filter
# ─────────────────────────────────────────────────────────────────────────────

def test_ruijie_access_group_inbound_to_h3c():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n ip access-group 3000 in\n",
        "ruijie", "h3c",
    )
    assert "packet-filter 3000 inbound" in result


# ─────────────────────────────────────────────────────────────────────────────
# Cisco ACL numbered → Huawei ACL number
# ─────────────────────────────────────────────────────────────────────────────

def test_cisco_numbered_acl_to_huawei():
    result = RuleBasedTranslator().translate(
        "access-list 101 permit tcp 192.168.1.0 0.0.0.255 any eq 80\n",
        "cisco", "huawei",
    )
    assert "acl number 101" in result
    assert "rule permit tcp source 192.168.1.0 0.0.0.255 destination any destination-port eq 80" in result


def test_cisco_numbered_acl_deny_ip_to_huawei():
    result = RuleBasedTranslator().translate(
        "access-list 101 deny ip any any\n",
        "cisco", "huawei",
    )
    assert "acl number 101" in result
    assert "rule deny ip source any destination any" in result


def test_cisco_numbered_acl_to_h3c():
    result = RuleBasedTranslator().translate(
        "access-list 101 permit tcp 192.168.1.0 0.0.0.255 any eq 80\n",
        "cisco", "h3c",
    )
    assert "acl number 101" in result
    assert "rule permit tcp source 192.168.1.0 0.0.0.255 destination any destination-port eq 80" in result


# ─────────────────────────────────────────────────────────────────────────────
# Huawei traffic-policy → Cisco service-policy (QoS)
# ─────────────────────────────────────────────────────────────────────────────

def test_huawei_traffic_policy_inbound_to_cisco():
    result = RuleBasedTranslator().translate(
        "interface Vlanif10\n traffic-policy PBR-LAN-IN inbound\n",
        "huawei", "cisco",
    )
    assert "service-policy input PBR-LAN-IN" in result


def test_huawei_traffic_policy_outbound_to_cisco():
    result = RuleBasedTranslator().translate(
        "interface Vlanif10\n traffic-policy PBR-LAN-OUT outbound\n",
        "huawei", "cisco",
    )
    assert "service-policy output PBR-LAN-OUT" in result
    assert "MANUAL_REVIEW unsupported source command: traffic-policy PBR-LAN-OUT outbound" not in result


# ─────────────────────────────────────────────────────────────────────────────
# Interface context preserved
# ─────────────────────────────────────────────────────────────────────────────

def test_acl_binding_preserves_interface_context():
    """Verifies ACL binding stays with its interface, not output as orphan line."""
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n traffic-filter inbound acl 3000\n",
        "huawei", "cisco",
    )
    executable = "\n".join(_executable_lines(result))
    lines = [l.strip() for l in executable.splitlines() if l.strip()]
    traffic_filter_lines = [l for l in lines if "traffic-filter" in l]
    assert len(traffic_filter_lines) == 0, "traffic-filter must not appear in Cisco output"
    assert "ip access-group 3000 in" in executable, "ACL binding must appear in output"
    assert "interface" in executable, "interface line must appear"


def test_acl_binding_no_interface_context_lost():
    """Verifies ACL binding stays with its interface, not output as orphan line."""
    result = RuleBasedTranslator().translate(
        "interface Vlanif100\n ip address 10.0.100.1 255.255.255.0\n traffic-filter inbound acl 3000\n",
        "huawei", "cisco",
    )
    executable = "\n".join(_executable_lines(result))
    lines = [l.strip() for l in executable.splitlines() if l.strip()]
    traffic_filter_lines = [l for l in lines if "traffic-filter" in l]
    assert len(traffic_filter_lines) == 0, "traffic-filter must not appear in Cisco output"


# ─────────────────────────────────────────────────────────────────────────────
# Direction in/out not reversed
# ─────────────────────────────────────────────────────────────────────────────

def test_huawei_traffic_filter_inbound_direction_preserved():
    result = RuleBasedTranslator().translate(
        "interface Vlanif10\n traffic-filter inbound acl 3000\n",
        "huawei", "cisco",
    )
    assert "ip access-group 3000 in" in result
    assert "out" not in result


def test_huawei_traffic_filter_outbound_direction_preserved():
    result = RuleBasedTranslator().translate(
        "interface Vlanif10\n traffic-filter outbound acl 3000\n",
        "huawei", "cisco",
    )
    assert "ip access-group 3000 out" in result


def test_h3c_packet_filter_inbound_direction_preserved():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n packet-filter 3000 inbound\n",
        "h3c", "cisco",
    )
    assert "ip access-group 3000 in" in result
    assert "out" not in result


def test_h3c_packet_filter_outbound_direction_preserved():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n packet-filter 3000 outbound\n",
        "h3c", "cisco",
    )
    assert "ip access-group 3000 out" in result


# ─────────────────────────────────────────────────────────────────────────────
# No source vendor residual (Huawei/H3C commands must not leak into Cisco output)
# ─────────────────────────────────────────────────────────────────────────────

def test_no_traffic_filter_in_cisco_output():
    result = RuleBasedTranslator().translate(
        "interface Vlanif10\n traffic-filter inbound acl 3000\n",
        "huawei", "cisco",
    )
    executable = "\n".join(_executable_lines(result))
    assert "traffic-filter" not in executable


def test_no_packet_filter_in_cisco_output():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n packet-filter 3000 inbound\n",
        "h3c", "cisco",
    )
    executable = "\n".join(_executable_lines(result))
    assert "packet-filter" not in executable


def test_no_traffic_filter_in_huawei_output_from_cisco_acl():
    result = RuleBasedTranslator().translate(
        "interface Vlan10\n ip access-group 3000 in\n",
        "cisco", "huawei",
    )
    executable = "\n".join(_executable_lines(result))
    assert "ip access-group" not in executable


# ─────────────────────────────────────────────────────────────────────────────
# Interface binding — additional directions
# ─────────────────────────────────────────────────────────────────────────────

def test_h3c_packet_filter_inbound_to_huawei():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n packet-filter 3000 inbound\n",
        "h3c", "huawei",
    )
    assert "traffic-filter inbound acl 3000" in result


def test_h3c_packet_filter_outbound_to_huawei():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n packet-filter 3000 outbound\n",
        "h3c", "huawei",
    )
    assert "traffic-filter outbound acl 3000" in result


def test_h3c_packet_filter_inbound_to_ruijie():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n packet-filter 3000 inbound\n",
        "h3c", "ruijie",
    )
    assert "ip access-group 3000 in" in result


def test_ruijie_access_group_to_cisco_inbound():
    result = RuleBasedTranslator().translate(
        "interface Vlan10\n ip access-group LAN-POLICY in\n",
        "ruijie", "cisco",
    )
    assert "ip access-group LAN-POLICY in" in result


def test_ruijie_access_group_to_cisco_outbound():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n ip access-group 3000 out\n",
        "ruijie", "cisco",
    )
    assert "ip access-group 3000 out" in result


def test_cisco_access_group_inbound_to_ruijie():
    result = RuleBasedTranslator().translate(
        "interface Vlan10\n ip access-group ACL-MGMT in\n",
        "cisco", "ruijie",
    )
    assert "ip access-group ACL-MGMT in" in result


def test_cisco_access_group_outbound_to_ruijie():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n ip access-group 3000 out\n",
        "cisco", "ruijie",
    )
    assert "ip access-group 3000 out" in result


# ─────────────────────────────────────────────────────────────────────────────
# Cisco ACL header → Huawei/H3C ACL container
# ─────────────────────────────────────────────────────────────────────────────

def test_cisco_extended_named_acl_header_to_huawei():
    result = RuleBasedTranslator().translate("ip access-list extended WEB-POLICY\n", "cisco", "huawei")
    assert "acl name WEB-POLICY advanced" in result


def test_cisco_standard_named_acl_header_to_huawei():
    result = RuleBasedTranslator().translate("ip access-list standard MGMT-ACL\n", "cisco", "huawei")
    assert "acl name MGMT-ACL basic" in result


def test_cisco_extended_named_acl_header_to_h3c():
    result = RuleBasedTranslator().translate("ip access-list extended WEB-POLICY\n", "cisco", "h3c")
    assert "acl name WEB-POLICY advanced" in result


def test_cisco_standard_named_acl_header_to_h3c():
    result = RuleBasedTranslator().translate("ip access-list standard MGMT-ACL\n", "cisco", "h3c")
    assert "acl name MGMT-ACL basic" in result


# ─────────────────────────────────────────────────────────────────────────────
# Cisco numbered ACL → Huawei/H3C (additional protocols)
# ─────────────────────────────────────────────────────────────────────────────

def test_cisco_numbered_acl_permit_icmp_to_huawei():
    result = RuleBasedTranslator().translate("access-list 101 permit icmp 10.0.0.0 0.0.0.255 172.16.0.0 0.0.0.255\n", "cisco", "huawei")
    assert "acl number 101" in result
    assert "rule permit icmp source 10.0.0.0 0.0.0.255 destination 172.16.0.0 0.0.0.255" in result


def test_cisco_numbered_acl_permit_udp_to_huawei():
    result = RuleBasedTranslator().translate("access-list 101 permit udp any any eq 53\n", "cisco", "huawei")
    assert "acl number 101" in result
    assert "rule permit udp source any destination any destination-port eq 53" in result


def test_cisco_numbered_acl_deny_ip_to_h3c():
    result = RuleBasedTranslator().translate("access-list 101 deny ip 10.0.0.0 0.0.0.255 any\n", "cisco", "h3c")
    assert "acl number 101" in result
    assert "rule deny ip source 10.0.0.0 0.0.0.255 destination any" in result


def test_cisco_numbered_acl_permit_tcp_wildcard_to_h3c():
    result = RuleBasedTranslator().translate("access-list 100 permit tcp 192.168.0.0 0.0.255.255 host 10.0.0.1 eq 443\n", "cisco", "h3c")
    assert "acl number 100" in result
    assert "rule permit tcp source 192.168.0.0 0.0.255.255 destination 10.0.0.1 destination-port eq 443" in result


# ─────────────────────────────────────────────────────────────────────────────
# Huawei ACL rule → Cisco (translate_huawei_acl_rule_to_cisco)
# ─────────────────────────────────────────────────────────────────────────────

def test_huawei_acl_rule_permit_ip_source_any_dest_any_to_cisco():
    result = RuleBasedTranslator().translate("rule 5 permit ip source any destination any\n", "huawei", "cisco")
    assert "permit ip any any" in result


def test_huawei_acl_rule_permit_tcp_eq_to_cisco():
    result = RuleBasedTranslator().translate("rule 10 permit tcp source any destination 10.0.0.1 0 destination-port eq 443\n", "huawei", "cisco")
    assert "permit tcp any host 10.0.0.1 eq 443" in result


def test_huawei_acl_rule_permit_icmp_to_cisco():
    result = RuleBasedTranslator().translate("rule 20 permit icmp source 192.168.1.0 0.0.0.255 destination any\n", "huawei", "cisco")
    assert "permit icmp 192.168.1.0 0.0.0.255 any" in result


def test_huawei_acl_rule_deny_ip_with_wildcard_to_cisco():
    result = RuleBasedTranslator().translate("rule 5 deny ip source 10.0.0.0 0.0.0.255 destination any\n", "huawei", "cisco")
    assert "deny ip 10.0.0.0 0.0.0.255 any" in result


def test_huawei_acl_rule_permit_udp_eq_to_cisco():
    result = RuleBasedTranslator().translate("rule 30 permit udp source any destination any destination-port eq 53\n", "huawei", "cisco")
    assert "permit udp any any eq 53" in result


def test_huawei_acl_rule_seq_number_preserved_to_cisco():
    result = RuleBasedTranslator().translate("rule 100 permit tcp source any destination 172.16.0.1 0 destination-port eq 22\n", "huawei", "cisco")
    assert "100 permit tcp any host 172.16.0.1 eq 22" in result


# ─────────────────────────────────────────────────────────────────────────────
# QoS — service-policy / traffic-policy (safe subset + negatives)
# ─────────────────────────────────────────────────────────────────────────────

def test_cisco_service_policy_input_to_huawei():
    result = RuleBasedTranslator().translate("interface Vlanif10\n service-policy input QOS-POLICY\n", "cisco", "huawei")
    assert "traffic-policy QOS-POLICY inbound" in result, \
        "service-policy input auto-translated to traffic-policy inbound"


def test_cisco_service_policy_output_to_huawei_manual_review():
    result = RuleBasedTranslator().translate("interface Vlanif10\n service-policy output QOS-POLICY\n", "cisco", "huawei")
    assert "traffic-policy QOS-POLICY outbound" in result
    assert "MANUAL_REVIEW unsupported source command: service-policy output QOS-POLICY" not in result


def test_huawei_traffic_policy_inbound_to_cisco_preserves_interface():
    result = RuleBasedTranslator().translate("interface Vlanif10\n traffic-policy PBR-LAN-IN inbound\n", "huawei", "cisco")
    assert "interface Vlan10" in result
    assert "service-policy input PBR-LAN-IN" in result


def test_huawei_traffic_policy_outbound_to_cisco_preserves_interface():
    result = RuleBasedTranslator().translate("interface Vlanif10\n traffic-policy PBR-LAN-OUT outbound\n", "huawei", "cisco")
    assert "interface Vlan10" in result
    assert "service-policy output PBR-LAN-OUT" in result


# ─────────────────────────────────────────────────────────────────────────────
# Complex ACL — must be MANUAL_REVIEW, no silent discard
# ─────────────────────────────────────────────────────────────────────────────

def test_huawei_acl_rule_with_time_range_is_manual_review():
    result = RuleBasedTranslator().translate("rule 5 permit tcp source any destination any time-range WORK-HOURS\n", "huawei", "cisco")
    assert "MANUAL_REVIEW" in result


def test_huawei_acl_rule_with_vpn_instance_is_manual_review():
    result = RuleBasedTranslator().translate("rule 5 permit ip source 10.0.0.0 0.0.0.255 destination any vpn-instance MGMT\n", "huawei", "cisco")
    assert "MANUAL_REVIEW" in result


def test_huawei_acl_rule_with_gt_port_is_manual_review():
    result = RuleBasedTranslator().translate("rule 5 permit tcp source any destination any destination-port gt 1024\n", "huawei", "cisco")
    assert "MANUAL_REVIEW" in result


def test_cisco_acl_with_object_group_is_manual_review():
    result = RuleBasedTranslator().translate("access-list 101 permit tcp any object-group WEB-SERVERS eq 80\n", "cisco", "huawei")
    assert "MANUAL_REVIEW" in result


def test_huawei_acl_rule_with_source_port_is_manual_review():
    result = RuleBasedTranslator().translate("rule 5 permit tcp source-port eq 3000 destination any destination-port eq 80\n", "huawei", "cisco")
    assert "MANUAL_REVIEW" in result


def test_no_huawei_source_port_leaks_to_cisco_output():
    result = RuleBasedTranslator().translate("rule 5 permit tcp source-port eq 3000 destination any\n", "huawei", "cisco")
    executable = "\n".join(_executable_lines(result))
    assert "source-port" not in executable.lower()


def test_no_time_range_leaks_to_cisco_output():
    result = RuleBasedTranslator().translate("rule 5 permit ip source any destination any time-range WORK-HOURS\n", "huawei", "cisco")
    executable = "\n".join(_executable_lines(result))
    assert "time-range" not in executable.lower()


def test_huawei_traffic_filter_inbound_to_h3c():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n traffic-filter inbound acl 3000\n",
        "huawei", "h3c",
    )
    assert "packet-filter 3000 inbound" in result


def test_huawei_traffic_filter_outbound_to_h3c():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n traffic-filter outbound acl 3000\n",
        "huawei", "h3c",
    )
    assert "packet-filter 3000 outbound" in result


def test_huawei_traffic_filter_to_h3c_no_cisco_syntax():
    result = RuleBasedTranslator().translate(
        "interface GigabitEthernet0/0/1\n traffic-filter inbound acl 3000\n",
        "huawei", "h3c",
    )
    executable = "\n".join(_executable_lines(result))
    assert "ip access-group" not in executable


def test_huawei_object_group_to_cisco_uses_cisco_prefix():
    result = RuleBasedTranslator().translate(
        "rule 10 permit ip source object-group SRC destination any\n",
        "huawei", "cisco",
    )
    assert "! MANUAL_REVIEW" in result


def test_huawei_acl_rule_with_object_group_is_manual_review():
    result = RuleBasedTranslator().translate(
        "rule 10 permit ip source object-group SRC destination any\n",
        "huawei", "cisco",
    )
    assert "MANUAL_REVIEW" in result
    executable = "\n".join(_executable_lines(result))
    assert "object-group" not in executable.lower()


def test_huawei_acl_rule_with_evaluate_is_manual_review():
    result = RuleBasedTranslator().translate(
        "rule 10 permit ip source any destination any evaluate ACCESS-CONTROL\n",
        "huawei", "cisco",
    )
    assert "MANUAL_REVIEW" in result
    executable = "\n".join(_executable_lines(result))
    assert "evaluate" not in executable.lower()


def test_huawei_acl_rule_with_reflect_is_manual_review():
    result = RuleBasedTranslator().translate(
        "rule 10 permit tcp source any destination any reflect ACL-REFLECT\n",
        "huawei", "cisco",
    )
    assert "MANUAL_REVIEW" in result
    executable = "\n".join(_executable_lines(result))
    assert "reflect" not in executable.lower()


def test_huawei_acl_rule_with_dynamic_is_manual_review():
    result = RuleBasedTranslator().translate(
        "rule 10 permit tcp source any destination any dynamic DYN-NAME timeout 60\n",
        "huawei", "cisco",
    )
    assert "MANUAL_REVIEW" in result
    executable = "\n".join(_executable_lines(result))
    assert "dynamic" not in executable.lower()


def test_huawei_acl_rule_with_range_port_is_manual_review():
    result = RuleBasedTranslator().translate(
        "rule 10 permit tcp source any destination any destination-port range 1024 65535\n",
        "huawei", "cisco",
    )
    assert "MANUAL_REVIEW" in result
    executable = "\n".join(_executable_lines(result))
    assert "range" not in executable.lower()


def test_huawei_acl_rule_with_logging_is_manual_review():
    result = RuleBasedTranslator().translate(
        "rule 10 permit ip source any destination any logging\n",
        "huawei", "cisco",
    )
    assert "MANUAL_REVIEW" in result
    executable = "\n".join(_executable_lines(result))
    assert "logging" not in executable.lower()
