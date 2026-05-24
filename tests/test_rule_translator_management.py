# -*- coding: utf-8 -*-
"""Tests for management-plane (AAA/SNMP/NTP/logging/hostname) fallback translation."""

import pytest
from core.rule_translator import RuleBasedTranslator


def _executable_lines(text: str):
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith(("```", "!", "#"))
    ]


# ─────────────────────────────────────────────────────────────────────────────
# hostname / sysname
# ─────────────────────────────────────────────────────────────────────────────

def test_huawei_sysname_to_cisco():
    result = RuleBasedTranslator().translate("sysname HW-SW\n", "huawei", "cisco")
    assert "hostname HW-SW" in result


def test_cisco_hostname_to_huawei():
    result = RuleBasedTranslator().translate("hostname C-SW\n", "cisco", "huawei")
    assert "sysname C-SW" in result


def test_h3c_sysname_to_cisco():
    result = RuleBasedTranslator().translate("sysname H3C-SW\n", "h3c", "cisco")
    assert "hostname H3C-SW" in result


def test_ruijie_hostname_to_huawei():
    result = RuleBasedTranslator().translate("hostname RJ-SW\n", "ruijie", "huawei")
    assert "sysname RJ-SW" in result


def test_cisco_hostname_to_h3c():
    result = RuleBasedTranslator().translate("hostname C-SW\n", "cisco", "h3c")
    assert "sysname C-SW" in result


def test_cisco_hostname_to_ruijie():
    result = RuleBasedTranslator().translate("hostname C-SW\n", "cisco", "ruijie")
    assert "hostname C-SW" in result


# ─────────────────────────────────────────────────────────────────────────────
# NTP
# ─────────────────────────────────────────────────────────────────────────────

def test_cisco_ntp_server_to_huawei():
    result = RuleBasedTranslator().translate("ntp server 10.0.0.1\n", "cisco", "huawei")
    assert "ntp-service unicast-server 10.0.0.1" in result


def test_cisco_ntp_server_with_vrf_to_huawei():
    result = RuleBasedTranslator().translate("ntp server vrf MGMT 10.0.0.2\n", "cisco", "huawei")
    assert "ntp-service unicast-server 10.0.0.2 vrf mgmt" in result


def test_huawei_ntp_to_cisco():
    result = RuleBasedTranslator().translate("ntp-service unicast-server 10.0.0.1\n", "huawei", "cisco")
    assert "ntp server 10.0.0.1" in result


def test_huawei_ntp_vrf_to_cisco_becomes_manual_review():
    result = RuleBasedTranslator().translate("ntp-service unicast-server 10.0.0.1 vrf MGMT\n", "huawei", "cisco")
    assert "ntp server 10.0.0.1" in result
    assert "MANUAL_REVIEW" in result


def test_cisco_ntp_source_interface_to_huawei():
    result = RuleBasedTranslator().translate("ntp source-interface Loopback0\n", "cisco", "huawei")
    assert "ntp-service source-interface LoopBack0" in result


def test_ruijie_ntp_to_huawei():
    result = RuleBasedTranslator().translate("ntp server 10.0.0.1\n", "ruijie", "huawei")
    assert "ntp-service unicast-server 10.0.0.1" in result


def test_huawei_ntp_to_h3c():
    result = RuleBasedTranslator().translate("ntp-service unicast-server 10.0.0.1\n", "huawei", "h3c")
    assert "ntp server 10.0.0.1" in result


def test_huawei_ntp_to_ruijie():
    result = RuleBasedTranslator().translate("ntp-service unicast-server 10.0.0.1\n", "huawei", "ruijie")
    assert "ntp server 10.0.0.1" in result


# ─────────────────────────────────────────────────────────────────────────────
# logging / info-center
# ─────────────────────────────────────────────────────────────────────────────

def test_cisco_logging_host_to_huawei():
    result = RuleBasedTranslator().translate("logging host 10.0.0.1\n", "cisco", "huawei")
    assert "info-center loghost 10.0.0.1" in result


def test_cisco_logging_host_with_port_to_huawei():
    result = RuleBasedTranslator().translate("logging host 10.0.0.1 udp-port 8514\n", "cisco", "huawei")
    assert "info-center loghost 10.0.0.1" in result
    assert "udp-port 8514" in result


def test_huawei_info_center_to_cisco():
    result = RuleBasedTranslator().translate("info-center loghost 10.0.0.1\n", "huawei", "cisco")
    assert "logging host 10.0.0.1" in result


def test_huawei_info_center_with_port_to_cisco():
    result = RuleBasedTranslator().translate("info-center loghost 10.0.0.1 udp-port 8514\n", "huawei", "cisco")
    assert "logging host 10.0.0.1" in result
    assert "udp-port 8514" in result


def test_cisco_logging_source_interface_to_huawei():
    result = RuleBasedTranslator().translate("logging source-interface GigabitEthernet0/1\n", "cisco", "huawei")
    assert "info-center source" in result


def test_huawei_info_center_to_h3c():
    result = RuleBasedTranslator().translate("info-center loghost 10.0.0.1\n", "huawei", "h3c")
    assert "logging 10.0.0.1" in result


def test_cisco_logging_to_ruijie():
    result = RuleBasedTranslator().translate("logging host 10.0.0.1\n", "cisco", "ruijie")
    assert "logging 10.0.0.1" in result


# ─────────────────────────────────────────────────────────────────────────────
# AAA / local-user / username — password must not appear in executable output
# ─────────────────────────────────────────────────────────────────────────────

def test_huawei_local_user_with_cipher_to_cisco_redacted():
    result = RuleBasedTranslator().translate(
        "local-user admin password irreversible-cipher $1$a$b\n",
        "huawei", "cisco",
    )
    executable = "\n".join(_executable_lines(result))
    assert "$1$a$b" not in executable
    assert "MANUAL_REVIEW" in result


def test_huawei_local_user_plaintext_password_to_cisco_redacted():
    result = RuleBasedTranslator().translate(
        "local-user admin password simple-text Admin123\n",
        "huawei", "cisco",
    )
    executable = "\n".join(_executable_lines(result))
    assert "Admin123" not in executable
    assert "MANUAL_REVIEW" in result


def test_cisco_username_with_password_to_huawei_redacted():
    result = RuleBasedTranslator().translate(
        "username admin password Admin123\n",
        "cisco", "huawei",
    )
    executable = "\n".join(_executable_lines(result))
    assert "Admin123" not in executable
    assert "MANUAL_REVIEW" in result


def test_cisco_username_with_secret_to_huawei_redacted():
    result = RuleBasedTranslator().translate(
        "username admin secret 5$a$b$c\n",
        "cisco", "huawei",
    )
    executable = "\n".join(_executable_lines(result))
    assert "$a$b$c" not in executable
    assert "MANUAL_REVIEW" in result


def test_cisco_aaa_new_model_passthrough():
    result = RuleBasedTranslator().translate("aaa new-model\n", "cisco", "huawei")
    assert "aaa new-model" in result


def test_huawei_local_user_without_password_to_cisco_manual_review():
    result = RuleBasedTranslator().translate("local-user admin\n", "huawei", "cisco")
    assert "MANUAL_REVIEW" in result


def test_cisco_username_without_password_to_huawei_manual_review():
    result = RuleBasedTranslator().translate("username admin\n", "cisco", "huawei")
    assert "MANUAL_REVIEW" in result


def test_huawei_local_user_service_type_to_cisco_manual_review():
    result = RuleBasedTranslator().translate("local-user admin service-type telnet\n", "huawei", "cisco")
    assert "MANUAL_REVIEW" in result


def test_ruijie_local_user_to_huawei_redacted():
    result = RuleBasedTranslator().translate("local-user admin password cipher $x$y\n", "ruijie", "huawei")
    executable = "\n".join(_executable_lines(result))
    assert "$x$y" not in executable
    assert "MANUAL_REVIEW" in result


def test_h3c_username_to_cisco_redacted():
    result = RuleBasedTranslator().translate("username admin password cipher $abc\n", "h3c", "cisco")
    executable = "\n".join(_executable_lines(result))
    assert "$abc" not in executable
    assert "MANUAL_REVIEW" in result


# ─────────────────────────────────────────────────────────────────────────────
# SNMP — community strings must not leak in executable output
# ─────────────────────────────────────────────────────────────────────────────

def test_huawei_snmp_community_cipher_to_cisco_redacted():
    result = RuleBasedTranslator().translate(
        "snmp-agent community read cipher PUBLIC acl 2002\n",
        "huawei", "cisco",
    )
    executable = "\n".join(_executable_lines(result))
    assert "PUBLIC" not in executable
    assert "MANUAL_REVIEW" in result


def test_huawei_snmp_trap_enable_to_cisco():
    result = RuleBasedTranslator().translate("snmp-agent trap enable\n", "huawei", "cisco")
    assert "snmp-server enable traps" in result


def test_cisco_snmp_trap_enable_to_huawei():
    result = RuleBasedTranslator().translate("snmp-server enable traps\n", "cisco", "huawei")
    assert "snmp-agent trap enable" in result


def test_cisco_snmp_trap_source_loopback_to_huawei():
    result = RuleBasedTranslator().translate("snmp-server trap-source Loopback0\n", "cisco", "huawei")
    assert "snmp-agent trap source LoopBack0" in result


def test_huawei_snmp_v3_host_to_cisco_trap_host():
    result = RuleBasedTranslator().translate(
        "snmp-agent target-host trap address udp-domain 10.0.0.1 params securityname snmpuser v3 privacy\n",
        "huawei", "cisco",
    )
    assert "snmp-server host 10.0.0.1 version 3 priv snmpuser" in result


def test_huawei_snmp_other_to_cisco_manual_review():
    result = RuleBasedTranslator().translate("snmp-agent sys-info contact NetAdmin\n", "huawei", "cisco")
    assert "MANUAL_REVIEW" in result


def test_cisco_snmp_to_huawei_manual_review():
    result = RuleBasedTranslator().translate("snmp-server location DC-Floor3\n", "cisco", "huawei")
    assert "MANUAL_REVIEW" in result


def test_huawei_snmp_v3_host_to_h3c():
    result = RuleBasedTranslator().translate(
        "snmp-agent target-host trap address udp-domain 10.0.0.1 params securityname snmpuser v3 privacy\n",
        "huawei", "h3c",
    )
    assert "MANUAL_REVIEW" in result


def test_huawei_snmp_v3_host_to_ruijie():
    result = RuleBasedTranslator().translate(
        "snmp-agent target-host trap address udp-domain 10.0.0.1 params securityname snmpuser v3 privacy\n",
        "huawei", "ruijie",
    )
    assert "MANUAL_REVIEW" in result


# ─────────────────────────────────────────────────────────────────────────────
# Unknown management commands → MANUAL_REVIEW (no source vendor leaks)
# ─────────────────────────────────────────────────────────────────────────────

def test_unknown_cisco_management_command_to_huawei_manual_review():
    result = RuleBasedTranslator().translate("aaa authentication login default group radius\n", "cisco", "huawei")
    executable = "\n".join(_executable_lines(result))
    assert "aaa authentication" not in executable
    assert "MANUAL_REVIEW" in result


def test_unknown_huawei_management_command_to_cisco_manual_review():
    result = RuleBasedTranslator().translate("aaa authentication login default group radius\n", "huawei", "cisco")
    executable = "\n".join(_executable_lines(result))
    assert "aaa authentication" not in executable
    assert "MANUAL_REVIEW" in result