# -*- coding: utf-8 -*-
"""Acceptance test: realistic Huawei→Cisco safe fallback report."""

import pytest
from core.graph import State
from core.graph.nodes import FallbackNode


def _executable_lines(text: str):
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip()
        and not line.strip().startswith(("!", "#", "```"))
    ]


REALISTIC_HUAWEI_CONFIG = """sysname Core-SW
vlan batch 10 20 30 40 50
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
interface Vlanif20
 ip address 10.0.20.1 255.255.255.0
interface GigabitEthernet0/0/1
 port link-type trunk
 port trunk permit vlan 10 20
interface GigabitEthernet0/0/2
 port link-type access
 port default vlan 30
acl number 3000
 rule 5 permit ip source 10.0.0.0 0.0.0.255 destination 10.0.10.0 0.0.0.255
 rule 10 deny tcp destination-port eq 80
acl number 3001
 rule 5 permit udp source 10.0.20.0 0.0.0.255
traffic classifier ACLS operator and
 if-match acl 3000
traffic behavior ACL_PERMIT
 traffic filter ip
qos policy PBR_ACL
 classifier ACLS behavior ACL_PERMIT
aaa
 local-user admin password irreversible-cipher $1a$=MD5~~~~
 local-user admin privilege level 15
 local-user netuser password irreversible-cipher $1b$=MD5~~~~
 authentication-profile default_authen_profile
 authorization-profile default_author_profile
snmp-agent community read cipher public123
snmp-agent sysinfo location DataCenter-Floor3
info-center loghost 10.0.100.99
info-center source default channel 2 log level warning
nqa test-instance admin icmp_test
 nqa test-instance admin icmp_test
 test-type icmp
 destination-ip 10.0.10.254
 frequency 10
 probe-count 2
ip route-static 0.0.0.0 0.0.0.0 10.0.0.1
ip route-static 10.0.50.0 255.255.255.0 10.0.20.254
stp enable
stp mode rstp
bfd
ip vpn-instance MGMT
 ipv4-family
 route-distinguisher 100:1
"""


def test_realistic_fallback_report_structure():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")
    state.set("config_text", REALISTIC_HUAWEI_CONFIG)

    FallbackNode().execute(state)
    translated = state.get("translated_config")
    executable = "\n".join(_executable_lines(translated))

    assert "人工复核摘要" in translated, "Report must include Chinese human-readable summary"
    assert "BEGIN_DETERMINISTIC_FALLBACK" in translated, "Report must wrap deterministic fallback"
    assert "END_DETERMINISTIC_FALLBACK" in translated
    assert "fallback_reason=" in translated
    assert "block_count=" in translated


def test_realistic_fallback_contains_deterministic_converted_blocks():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")
    state.set("config_text", REALISTIC_HUAWEI_CONFIG)

    FallbackNode().execute(state)
    translated = state.get("translated_config")
    executable = "\n".join(_executable_lines(translated))

    assert "hostname Core-SW" in executable
    assert "vlan 10,20,30,40,50" in executable
    assert "interface Vlan10" in executable or "interface Vlanif10" not in executable
    assert "interface GigabitEthernet0/0/1" in executable or "switchport" in executable


def test_realistic_fallback_has_no_source_vendor_residue():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")
    state.set("config_text", REALISTIC_HUAWEI_CONFIG)

    FallbackNode().execute(state)
    translated = state.get("translated_config")
    executable = "\n".join(_executable_lines(translated))

    assert "vlan batch" not in executable
    assert "traffic classifier" not in executable
    assert "local-user" not in executable
    assert "info-center" not in executable
    assert "interface Vlanif10" not in executable
    assert "interface Vlanif20" not in executable


def test_realistic_fallback_detail_blocks_capped():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")
    state.set("config_text", REALISTIC_HUAWEI_CONFIG)

    FallbackNode().execute(state)
    translated = state.get("translated_config")

    detail_lines = [
        l for l in translated.splitlines()
        if "MANUAL_REVIEW_BLOCK" in l and l.strip().startswith("!")
    ]
    visible_count = sum(
        1 for l in translated.splitlines()
        if "MANUAL_REVIEW_BLOCK" in l and l.strip().startswith("!")
    )

    block_count_line = next(
        (l for l in translated.splitlines() if l.strip().startswith("! block_count=")), None
    )
    assert block_count_line is not None
    total = int(block_count_line.split("=")[1].strip())

    if total > 20:
        assert "... 还有" in translated
        assert visible_count <= 20


def test_realistic_fallback_friendly_reason():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")
    state.set("config_text", "vlan 10\n")

    FallbackNode().execute(state)
    translated = state.get("translated_config")

    reason_line = next(
        (l for l in translated.splitlines() if l.strip().startswith("! fallback_reason=")), None
    )
    assert reason_line is not None
    reason = reason_line.split("=", 1)[1].strip()
    assert "第 0 项不是对象" not in reason
    assert len(reason) < 200


def test_realistic_fallback_validation_warnings_clean():
    state = State()
    state.set("from_vendor", "huawei")
    state.set("to_vendor", "cisco")
    state.set("translate_error", "LLM 输出校验失败: 第 0 项不是对象")
    state.set("config_text", REALISTIC_HUAWEI_CONFIG)

    FallbackNode().execute(state)
    translated = state.get("translated_config")

    assert "第 0 项不是对象" not in translated
    assert "VRF RD/route-target 格式异常" not in translated
    assert "policy/history/number/irreversible-cipher" not in translated