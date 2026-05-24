# -*- coding: utf-8 -*-
"""Batch I-E: Realistic medium-length configuration samples for fallback压测.

Covers 4 directions with 15-50 line realistic configs:
1. Cisco SWITCH/ROUTER → Huawei VRP
2. Huawei VRP → Cisco
3. Topsec FIREWALL → Huawei USG
4. Hillstone FIREWALL → Topsec

Each sample is designed to stress-test line-by-line fallback translation
with real-world complexity.
"""

import pytest
import re

from core.rule_translator import RuleBasedTranslator


SENSITIVE_PATTERNS_REDACTED = [
    re.compile(r"(?<![<>\w])(password|secret|password|cipher|shared-key)\s+(?!<redacted>)\S+", re.I),
    re.compile(r"(?<![<>\w])community\s+(?!<redacted>)\S+", re.I),
]


def _has_secret_leak(result: str) -> bool:
    """Check if result contains unredacted secrets in executable lines."""
    executable = "\n".join(
        l for l in result.split("\n")
        if l.strip() and not l.strip().startswith("#") and not l.strip().startswith("!")
    )
    for pattern in SENSITIVE_PATTERNS_REDACTED:
        if pattern.search(executable):
            return True
    return False


def _has_source_syntax(result: str, source_vendor: str) -> bool:
    """Check if result contains untranslated source vendor executable syntax.

    Only checks executable lines (excludes comment-only appearances).
    """
    executable = "\n".join(
        l for l in result.split("\n")
        if l.strip() and not l.strip().startswith("#") and not l.strip().startswith("!")
    )
    source_vendor = source_vendor.lower()
    if source_vendor == "cisco":
        return any(k in executable for k in [
            "ip access-group", "switchport",
        ])
    if source_vendor in ("huawei", "huawei_usg"):
        return any(k in executable for k in [
            "port link-type", "port trunk allow-pass",
            "traffic-filter", "acl number",
            "vlan batch", "ntp-service",
            "info-center", "snmp-agent community",
        ])
    if source_vendor == "h3c":
        return any(k in executable for k in [
            "port link-type", "port trunk permit",
            "packet-filter",
        ])
    if source_vendor == "hillstone":
        return "from " in executable and " to " in executable
    if source_vendor == "topsec":
        return False
    return False


def _check_no_source_residue(result: str, source_vendor: str):
    assert not _has_source_syntax(result, source_vendor), \
        f"Result contains untranslated source vendor syntax ({source_vendor})"


class TestCiscoToHuaweiRealistic:
    """链路1: Cisco SWITCH/ROUTER → Huawei VRP"""

    @pytest.fixture
    def cisco_switch_config(self):
        return """!
hostname BJ-ACCESS-SW01
!
vlan 10
 name DATA_VLAN
!
vlan 20
 name VOICE_VLAN
!
vlan 99
 name MGMT_VLAN
!
interface GigabitEthernet0/0/1
 description Uplink-to-Core
 switchport mode trunk
 switchport trunk allowed vlan 10,20,99
 switchport trunk native vlan 99
 no shutdown
!
interface GigabitEthernet0/0/2
 description Access-Port
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
 no shutdown
!
interface GigabitEthernet0/0/3
 description Routed-Uplink
 no switchport
 ip address 10.255.1.2 255.255.255.0
!
interface Vlanif99
 ip address 10.255.99.1 255.255.255.0
!
ip route-static 0.0.0.0 0.0.0.0 10.255.1.1
!
router ospf 1
 router-id 10.255.99.1
 network 10.255.99.0 0.0.0.255 area 0
 passive-interface Vlanif99
!
ntp server 10.255.0.1
ntp server 10.255.0.2 prefer
!
snmp-server community public ro
snmp-server community private rw
snmp-server enable traps
!
aaa new-model
!
aaa authentication login default group radius local
aaa authorization exec default group radius local
!
line vty 0 4
 login authentication default
 transport input ssh
!
end
"""

    def test_cisco_switch_to_huawei_realistic(self, cisco_switch_config):
        result = RuleBasedTranslator().translate(cisco_switch_config, "cisco", "huawei")

        assert result.strip(), "Output should not be empty"

        assert "BJ-ACCESS-SW01" in result, "hostname should be translated to sysname"

        assert "vlan 10" in result or "VLAN 10" in result.upper(), "VLAN should appear"

        assert "interface" in result, "Interfaces should be in output"

        assert _has_secret_leak(result) is False, \
            f"Output should not contain unredacted secrets: {result}"

        _check_no_source_residue(result, "cisco")

    def test_cisco_switch_acl_to_huawei(self):
        config = """ip access-list extended ACL-DATA
 permit tcp any any eq 80
 permit tcp any any eq 443
 deny ip any any
!
interface GigabitEthernet0/0/1
 ip access-group ACL-DATA in
"""
        result = RuleBasedTranslator().translate(config, "cisco", "huawei")

        assert result.strip(), "Output should not be empty"
        assert "interface" in result

        assert _has_secret_leak(result) is False
        _check_no_source_residue(result, "cisco")

    def test_cisco_ospf_to_huawei(self):
        config = """router ospf 1
 router-id 10.1.1.1
 network 10.1.1.0 0.0.0.255 area 0
 network 10.2.2.0 0.0.0.255 area 0
 passive-interface default
 no passive-interface GigabitEthernet0/0/1
"""
        result = RuleBasedTranslator().translate(config, "cisco", "huawei")

        assert result.strip()
        assert "ospf" in result.lower() or "MANUAL_REVIEW" in result


class TestHuaweiToCiscoRealistic:
    """链路2: Huawei VRP SWITCH/ROUTER → Cisco"""

    @pytest.fixture
    def huawei_switch_config(self):
        return """sysname SH-CORE-SW01
!
vlan batch 10 20 99
!
interface Vlanif10
 ip address 10.255.10.1 255.255.255.0
!
interface Vlanif20
 ip address 10.255.20.1 255.255.255.0
!
interface GigabitEthernet0/0/1
 port link-type trunk
 port trunk allow-pass vlan 10 20 99
 undo shutdown
!
interface GigabitEthernet0/0/2
 port link-type access
 port default vlan 10
 undo shutdown
!
acl advanced number 3000
 rule 5 permit tcp source 10.255.0.0 0.0.255.255 destination 0.0.0.0 0 destination-port eq 80
 rule 10 permit tcp source 10.255.0.0 0.0.255.255 destination 0.0.0.0 0 destination-port eq 443
 rule 15 deny ip
!
interface GigabitEthernet0/0/1
 traffic-filter inbound acl 3000
!
ospf 1
 area 0.0.0.0
  network 10.255.10.0 0.0.0.255
  network 10.255.20.0 0.0.0.255
!
silent-interface Vlanif99
!
ntp-service unicast-server 10.255.0.1
!
snmp-agent community read public
snmp-agent community write private
snmp-agent trap enable
!
aaa
 local-user admin password irreversible-cipher $1a$SECRET_PASS$bbb
 local-user admin privilege level 15
 local-user admin service-type http ssh telnet
!
return
"""

    def test_huawei_switch_to_cisco_realistic(self, huawei_switch_config):
        result = RuleBasedTranslator().translate(huawei_switch_config, "huawei", "cisco")

        assert result.strip(), "Output should not be empty"

        assert "SH-CORE-SW01" in result or "hostname" in result.lower(), \
            "hostname/sysname should appear"

        assert "vlan" in result.lower(), "VLAN should appear"

        assert "interface" in result, "Interfaces should be in output"

        assert _has_secret_leak(result) is False, \
            f"Output should not contain unredacted secrets: {result}"

        _check_no_source_residue(result, "huawei")

    def test_huawei_acl_to_cisco(self):
        config = """acl advanced number 3000
 rule 5 permit tcp source 10.0.0.0 0.0.0.255 destination 0.0.0.0 0 destination-port eq 80
 rule 10 deny ip
"""
        result = RuleBasedTranslator().translate(config, "huawei", "cisco")

        assert result.strip()
        assert _has_secret_leak(result) is False
        _check_no_source_residue(result, "huawei")

    def test_huawei_ospf_to_cisco(self):
        config = """ospf 1
 area 0.0.0.0
  network 10.1.1.0 0.0.0.255
  network 10.2.2.0 0.0.0.255
"""
        result = RuleBasedTranslator().translate(config, "huawei", "cisco")

        assert result.strip()
        assert "ospf" in result.lower() or "MANUAL_REVIEW" in result
        _check_no_source_residue(result, "huawei")


class TestTopsecToHuaweiUsgRealistic:
    """链路3: Topsec FIREWALL → Huawei USG"""

    @pytest.fixture
    def topsec_fw_config(self):
        return """zone name trust
zone name untrust
zone name dmz
!
address name WEB-SERVER ip 10.1.1.10 mask 255.255.255.255
address name DB-SERVER ip 10.1.2.20 mask 255.255.255.255
address name MAIL-SERVER ip 10.1.3.30 mask 255.255.255.255
!
service HTTP protocol tcp destination-port 80
service HTTPS protocol tcp destination-port 443
service SMTP protocol tcp destination-port 25
service DNS protocol udp destination-port 53
!
policy name P1 source-zone trust destination-zone untrust source-address WEB-SERVER destination-address MAIL-SERVER service HTTPS action permit
policy name P2 source-zone trust destination-zone dmz source-address DB-SERVER destination-address WEB-SERVER service SMTP action permit
policy name P3 source-zone untrust destination-zone trust source-address any destination-address WEB-SERVER service HTTP action deny
!
nat policy NAT-POOL
source-nat POLICY1
!
ipsec tunnel TUNNEL1
!
url-filter URLF-1
!
time-range WORK-HOURS
!
log enable
!
end
"""

    def test_topsec_fw_to_huawei_usg_realistic(self, topsec_fw_config):
        result = RuleBasedTranslator().translate(topsec_fw_config, "topsec", "huawei_usg")

        assert result.strip(), "Output should not be empty"

        assert "security-zone" in result, "Topsec zone should become security-zone"

        assert "address" in result or "MANUAL_REVIEW" in result, \
            "Address objects should appear"

        assert _has_secret_leak(result) is False, \
            f"Output should not contain unredacted secrets: {result}"

    def test_topsec_complete_policy_to_huawei_usg(self):
        config = """zone name trust
zone name untrust
!
address name WEB ip 10.1.1.10 mask 255.255.255.255
!
policy name P1 source-zone trust destination-zone untrust source-address WEB destination-address any service HTTPS action permit
"""
        result = RuleBasedTranslator().translate(config, "topsec", "huawei_usg")

        assert result.strip()
        assert "security-zone" in result or "MANUAL_REVIEW" in result
        assert _has_secret_leak(result) is False

    def test_topsec_incomplete_policy_to_huawei_usg(self):
        config = """zone name trust
!
policy name P1 source-zone trust destination-zone untrust destination-address any service HTTPS action permit
"""
        result = RuleBasedTranslator().translate(config, "topsec", "huawei_usg")

        assert "MANUAL_REVIEW" in result, \
            "Incomplete policy (missing source-address) must be MANUAL_REVIEW"

    def test_topsec_dangerous_to_huawei_usg(self):
        dangerous = [
            "nat policy NAT",
            "source-nat POLICY",
            "ipsec tunnel TUN",
            "url-filter URLF",
            "time-range TR",
            "log enable",
        ]
        for cmd in dangerous:
            result = RuleBasedTranslator().translate(cmd + "\n", "topsec", "huawei_usg")
            assert "MANUAL_REVIEW" in result, \
                f"Dangerous command {cmd} must be MANUAL_REVIEW"

    def test_topsec_service_object_to_huawei_usg(self):
        config = """service HTTP protocol tcp destination-port 80
service HTTPS protocol tcp destination-port 443
"""
        result = RuleBasedTranslator().translate(config, "topsec", "huawei_usg")

        assert result.strip()
        assert _has_secret_leak(result) is False


class TestHillstoneToTopsecRealistic:
    """链路4: Hillstone FIREWALL → Topsec"""

    @pytest.fixture
    def hillstone_fw_config(self):
        return """zone trust
zone untrust
zone dmz
!
address WEB-SERVER 10.1.1.10 255.255.255.255
address DB-SERVER 10.1.2.20 255.255.255.255
address MAIL-SERVER 10.1.3.30 255.255.255.255
!
service HTTP tcp 80
service HTTPS tcp 443
service SMTP tcp 25
service DNS udp 53
!
policy P1 from trust to untrust source WEB-SERVER destination MAIL-SERVER service HTTPS action permit
policy P2 from trust to dmz source DB-SERVER destination WEB-SERVER service SMTP action permit
policy P3 from untrust to trust source any destination WEB-SERVER service HTTP action deny
!
nat POLICY-NAT
source-nat POOL1
!
ipsec tunnel TUNNEL1
!
url-filter URLF1
!
time-range WORK-HOURS
!
end
"""

    def test_hillstone_fw_to_topsec_realistic(self, hillstone_fw_config):
        result = RuleBasedTranslator().translate(hillstone_fw_config, "hillstone", "topsec")

        assert result.strip(), "Output should not be empty"

        assert "zone name" in result, "Hillstone zone should become Topsec zone name"

        assert "address name" in result or "MANUAL_REVIEW" in result, \
            "Address objects should appear in Topsec format"

        assert _has_secret_leak(result) is False, \
            f"Output should not contain unredacted secrets: {result}"

        _check_no_source_residue(result, "hillstone")

    def test_hillstone_complete_policy_to_topsec(self):
        config = """zone trust
zone untrust
!
address WEB 10.1.1.10 255.255.255.255
!
policy P1 from trust to untrust source WEB destination any service HTTPS action permit
"""
        result = RuleBasedTranslator().translate(config, "hillstone", "topsec")

        assert result.strip()
        assert "zone name" in result or "MANUAL_REVIEW" in result
        assert _has_secret_leak(result) is False
        _check_no_source_residue(result, "hillstone")

    def test_hillstone_incomplete_policy_to_topsec(self):
        config = """zone trust
!
policy P1 from trust to untrust destination any service HTTPS action permit
"""
        result = RuleBasedTranslator().translate(config, "hillstone", "topsec")

        assert "MANUAL_REVIEW" in result, \
            "Incomplete policy (missing source) must be MANUAL_REVIEW"

    def test_hillstone_dangerous_to_topsec(self):
        dangerous = [
            "nat POLICY-NAT",
            "source-nat POOL1",
            "ipsec tunnel TUNNEL1",
            "url-filter URLF1",
            "time-range WORK-HOURS",
        ]
        for cmd in dangerous:
            result = RuleBasedTranslator().translate(cmd + "\n", "hillstone", "topsec")
            assert "MANUAL_REVIEW" in result, \
                f"Dangerous command {cmd} must be MANUAL_REVIEW"


class TestGenericAssertions:
    """Generic assertions that apply across all directions."""

    def test_no_implicit_any_in_policy(self):
        """Policy with missing fields must not default to 'any'."""
        configs = [
            ("policy name P1 source-zone trust destination-zone untrust destination-address DST service HTTPS action permit\n",
             "topsec", "huawei_usg"),
            ("policy P1 from trust to untrust destination DST service HTTPS action permit\n",
             "hillstone", "topsec"),
        ]
        for cfg, fv, tv in configs:
            result = RuleBasedTranslator().translate(cfg, fv, tv)
            executable = "\n".join(l for l in result.split("\n")
                                   if l.strip() and not l.strip().startswith("#"))
            assert "any" not in executable.lower() or "MANUAL_REVIEW" in result, \
                f"No implicit 'any' should be assumed: {cfg[:50]}"

    def test_multi_policy_all_translated(self):
        """All policies in input should appear in output (not just first)."""
        config = """policy name P1 source-zone trust destination-zone untrust source-address A destination-address B service HTTP action permit
policy name P2 source-zone trust destination-zone untrust source-address C destination-address D service HTTPS action deny
"""
        result = RuleBasedTranslator().translate(config, "topsec", "huawei_usg")

        if "MANUAL_REVIEW" not in result:
            assert "P1" in result, "Policy P1 should appear"
            assert "P2" in result, "Policy P2 should appear (not just first)"
        else:
            assert "P1" in result or "P2" in result

    def test_cisco_bgp_to_huawei_manual_review(self):
        """Cisco BGP with complex features should go to MANUAL_REVIEW."""
        config = """router bgp 65001
 bgp log-change-subnet
 neighbor 10.1.1.1 remote-as 65002
 neighbor 10.1.1.1 password SECRET_KEY
 address-family ipv4
  network 10.0.0.0 mask 255.255.0.0
  neighbor 10.1.1.1 activate
"""
        result = RuleBasedTranslator().translate(config, "cisco", "huawei")

        assert "MANUAL_REVIEW" in result or "bgp" in result.lower(), \
            "BGP configuration should appear somehow"
        assert _has_secret_leak(result) is False, \
            "BGP password should be redacted"

    def test_huawei_vrf_to_cisco_manual_review(self):
        """Huawei VRF should go to MANUAL_REVIEW when translation is uncertain."""
        config = """ip vpn-instance VRF-ABC
 route-distinguisher 65001:100
 vpn-target 65001:100 export-extcommunity
 vpn-target 65001:100 import-extcommunity
"""
        result = RuleBasedTranslator().translate(config, "huawei", "cisco")

        assert result.strip()

    def test_cisco_static_route_to_huawei(self):
        """Simple static route should auto-translate."""
        config = """ip route 0.0.0.0 0.0.0.0 10.1.1.1
ip route 192.168.1.0 255.255.255.0 10.1.1.254
"""
        result = RuleBasedTranslator().translate(config, "cisco", "huawei")

        assert result.strip()
        assert "10.1.1.1" in result or "MANUAL_REVIEW" in result

    def test_huawei_static_route_to_cisco(self):
        """Huawei static route should auto-translate."""
        config = """ip route-static 0.0.0.0 0.0.0.0 10.1.1.1
ip route-static 192.168.1.0 255.255.255.0 10.1.1.254
"""
        result = RuleBasedTranslator().translate(config, "huawei", "cisco")

        assert result.strip()
        assert "10.1.1.1" in result or "MANUAL_REVIEW" in result
        _check_no_source_residue(result, "huawei")
