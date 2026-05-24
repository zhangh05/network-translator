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