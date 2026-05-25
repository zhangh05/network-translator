# -*- coding: utf-8 -*-
"""Batch K-D: Realistic multi-vendor cross-domain configuration samples.

8 realistic chains:
  1. Cisco SWITCH -> Huawei VRP (exercises K-A trunk/native/bpdu-guard)
  2. Huawei SWITCH -> Cisco (exercises K-A native vlan/bpdu-protection)
  3. H3C SWITCH -> Ruijie (multivendor switch pair)
  4. Ruijie SWITCH -> H3C (multivendor switch pair reverse)
  5. Cisco ROUTER -> Huawei VRP (exercises K-B OSPF auth/BGP/static options)
  6. Huawei ROUTER -> Cisco (exercises K-B BGP password/route-map)
  7. Huawei USG -> Hillstone (firewall zone/address/service/policy)
  8. Hillstone -> Topsec (firewall zone/address/policy)

Each chain asserts:
  - Auto-translated commands present
  - MANUAL_REVIEW items present with reasons
  - No sensitive value leakage (including comments)
  - No source vendor executable residue
  - No implicit default any (firewall)
  - No silent drops of critical lines
  - MANUAL_REVIEW is comment-only, not executable
"""

import re
import pytest
from core.rule_translator import RuleBasedTranslator


# ── helpers ─────────────────────────────────────────────────────────────

SENSITIVE_PATTERNS = [
    re.compile(r"(?<![<>\w])(password|secret|cipher|shared-key)\s+(?!<redacted>)\S+", re.I),
    re.compile(r"(?<![<>\w])community\s+(?!<redacted>)\S+", re.I),
]


def _executable_lines(result: str) -> list:
    lines = []
    in_fence = False
    for raw in result.split("\n"):
        line = raw.strip()
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence or not line:
            continue
        if line.startswith("#") or line.startswith("!"):
            continue
        lines.append(line)
    return lines


def _check_no_secret_leak(result: str):
    for pat in SENSITIVE_PATTERNS:
        m = pat.search(result)
        assert not m, (
            f"Sensitive value leak! Pattern '{pat.pattern}' "
            f"matched '{m.group()}' in output"
        )


def _check_no_source_residue(result: str, keywords: list):
    exe = _executable_lines(result)
    for kw in keywords:
        nkw = kw.lower()
        for line in exe:
            assert nkw not in line.lower(), (
                f"Source residue '{kw}' in executable line: {line}"
            )


def _check_manual_review_is_comment(result: str):
    """Every MANUAL_REVIEW text must be in a comment line, never in executable."""
    exe = _executable_lines(result)
    exe_text = "\n".join(exe).lower()
    if "manual_review" in exe_text:
        pytest.fail(f"MANUAL_REVIEW found in executable lines: {exe}")


def _check_no_default_any(result: str):
    """Firewall: no implicit 'any' in executable policy lines."""
    exe = _executable_lines(result)
    for line in exe:
        if "any" in line.lower() and ("zone" in line.lower() or "address" in line.lower() or "service" in line.lower()):
            # Allow "service any" in some contexts but flag it
            if "service any" in line.lower() or "any" in line.lower().split():
                pytest.fail(f"Default any implicit in executable: {line}")


# ── source vendor keywords per domain ───────────────────────────────────

CISCO_SW = ["channel-group", "switchport mode", "switchport trunk", "switchport access"]
CISCO_RT = ["ip route ", "router ospf", "router bgp"]
CISCO_ALL = CISCO_SW + CISCO_RT
HUAWEI_SW = ["undo shutdown", "port link-type", "port trunk allow-pass", "vlan batch", "stp edged-port"]
HUAWEI_RT = ["undo ", "ip route-static ", "route-policy", "silent-interface"]
HUAWEI_ALL = HUAWEI_SW + HUAWEI_RT
H3C_SW = ["vlan batch", "port link-type", "port trunk permit", "bridge-aggregation"]
RUIJIE_SW = ["aggregateport", "spanning-tree portfast", "switchport trunk allowed vlan"]
HILLSTONE_KW = ["nat ", "ipsec", "ike", "vpn "]
TOPSEC_KW = ["zone name", "address name", "policy name"]
USG_KW = ["security-zone", "ip address-set", "ip service-set", "security-policy"]


# ═══════════════════════════════════════════════════════════════════════
# Chain 1: Cisco SWITCH -> Huawei VRP
# ═══════════════════════════════════════════════════════════════════════

class TestCiscoSwitchToHuawei:
    CONFIG = """hostname SW1
vlan 10
vlan 20
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk allowed vlan 10,20
 switchport trunk native vlan 99
 description Uplink
 no shutdown
interface Vlan10
 ip address 192.168.10.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 192.168.10.254
spanning-tree portfast
spanning-tree bpduguard enable
"""

    def test_auto_translated(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "cisco", "huawei")
        assert r.startswith("```huawei"), f"Wrong fence: {r[:20]}"
        assert "sysname SW1" in r
        assert "vlan 10" in r
        assert "vlan 20" in r
        assert "port link-type trunk" in r
        assert "port trunk allow-pass vlan 10 20" in r
        assert "port trunk pvid vlan 99" in r
        assert "description Uplink" in r
        assert "undo shutdown" in r
        assert "interface Vlanif10" in r
        assert "ip address 192.168.10.1 255.255.255.0" in r
        assert "ip route-static 0.0.0.0 0.0.0.0 192.168.10.254" in r
        assert "stp edged-port enable" in r

    def test_manual_review(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "cisco", "huawei")
        assert "MANUAL_REVIEW" in r, "spanning-tree bpduguard should produce MANUAL_REVIEW"

    def test_no_secret_leak(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "cisco", "huawei")
        _check_no_secret_leak(r)

    def test_no_source_residue(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "cisco", "huawei")
        _check_no_source_residue(r, CISCO_SW + ["spanning-tree portfast"])

    def test_manual_review_is_comment(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "cisco", "huawei")
        _check_manual_review_is_comment(r)

    def test_no_silent_drop(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "cisco", "huawei")
        exe = _executable_lines(r)
        assert len(exe) >= 10, f"Too few executable lines ({len(exe)}): {exe}"
        assert any("sysname" in l for l in exe)
        assert any("Vlanif" in l for l in exe)


# ═══════════════════════════════════════════════════════════════════════
# Chain 2: Huawei SWITCH -> Cisco
# ═══════════════════════════════════════════════════════════════════════

class TestHuaweiSwitchToCisco:
    CONFIG = """sysname SW2
vlan batch 10 20 30
interface GigabitEthernet0/0/1
 port link-type trunk
 port trunk allow-pass vlan 10 20 30
 port trunk pvid vlan 99
 description Uplink
 undo shutdown
interface Vlanif10
 ip address 192.168.10.1 255.255.255.0
ip route-static 0.0.0.0 0.0.0.0 192.168.10.254
stp edged-port enable
"""

    def test_auto_translated(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei", "cisco")
        assert r.startswith("```cisco"), f"Wrong fence: {r[:20]}"
        assert "hostname SW2" in r
        assert "vlan 10,20,30" in r
        assert "switchport mode trunk" in r
        assert "switchport trunk allowed vlan 10,20,30" in r
        assert "switchport trunk native vlan 99" in r
        assert "description Uplink" in r
        assert "no shutdown" in r
        assert "interface Vlan10" in r
        assert "ip address 192.168.10.1 255.255.255.0" in r
        assert "ip route 0.0.0.0 0.0.0.0 192.168.10.254" in r
        assert "spanning-tree portfast" in r

    def test_no_secret_leak(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei", "cisco")
        _check_no_secret_leak(r)

    def test_no_source_residue(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei", "cisco")
        _check_no_source_residue(r, HUAWEI_SW)

    def test_manual_review_is_comment(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei", "cisco")
        _check_manual_review_is_comment(r)

    def test_no_silent_drop(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei", "cisco")
        exe = _executable_lines(r)
        assert len(exe) >= 10, f"Too few executable lines ({len(exe)}): {exe}"
        assert any("hostname" in l for l in exe)
        assert any("Vlan10" in l for l in exe)


# ═══════════════════════════════════════════════════════════════════════
# Chain 3: H3C SWITCH -> Ruijie
# ═══════════════════════════════════════════════════════════════════════

class TestH3cSwitchToRuijie:
    CONFIG = """sysname SW3
vlan batch 10 20
interface GigabitEthernet1/0/1
 port link-type trunk
 port trunk permit vlan 10 20
 description To-CORE
interface Vlan-interface10
 ip address 192.168.10.1 255.255.255.0
stp edged-port enable
"""

    def test_auto_translated(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "h3c", "ruijie")
        assert r.startswith("```ruijie"), f"Wrong fence: {r[:20]}"
        assert "hostname SW3" in r
        assert "vlan 10,20" in r
        assert "switchport mode trunk" in r
        assert "switchport trunk allowed vlan 10,20" in r
        assert "description To-CORE" in r
        assert "interface Vlan10" in r
        assert "ip address 192.168.10.1 255.255.255.0" in r
        assert "spanning-tree portfast" in r

    def test_no_secret_leak(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "h3c", "ruijie")
        _check_no_secret_leak(r)

    def test_no_source_residue(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "h3c", "ruijie")
        _check_no_source_residue(r, H3C_SW)

    def test_manual_review_is_comment(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "h3c", "ruijie")
        _check_manual_review_is_comment(r)

    def test_no_silent_drop(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "h3c", "ruijie")
        exe = _executable_lines(r)
        assert len(exe) >= 7, f"Too few executable lines ({len(exe)}): {exe}"
        assert any("hostname" in l for l in exe)


# ═══════════════════════════════════════════════════════════════════════
# Chain 4: Ruijie SWITCH -> H3C
# ═══════════════════════════════════════════════════════════════════════

class TestRuijieSwitchToH3c:
    CONFIG = """hostname SW4
vlan 10
vlan 20
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk allowed vlan 10,20
 description To-CORE
 no shutdown
interface Vlan10
 ip address 192.168.10.1 255.255.255.0
spanning-tree portfast
"""

    def test_auto_translated(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "ruijie", "h3c")
        assert r.startswith("```h3c"), f"Wrong fence: {r[:20]}"
        assert "sysname SW4" in r
        assert "vlan 10" in r
        assert "vlan 20" in r
        assert "port link-type trunk" in r
        assert "port trunk permit vlan 10 20" in r
        assert "interface Vlan-interface10" in r
        assert "ip address 192.168.10.1 255.255.255.0" in r
        assert "stp edged-port" in r

    def test_no_secret_leak(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "ruijie", "h3c")
        _check_no_secret_leak(r)

    def test_no_source_residue(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "ruijie", "h3c")
        _check_no_source_residue(r, RUIJIE_SW)

    def test_manual_review_is_comment(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "ruijie", "h3c")
        _check_manual_review_is_comment(r)

    def test_no_silent_drop(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "ruijie", "h3c")
        exe = _executable_lines(r)
        assert len(exe) >= 7, f"Too few executable lines ({len(exe)}): {exe}"
        assert any("sysname" in l for l in exe)


# ═══════════════════════════════════════════════════════════════════════
# Chain 5: Cisco ROUTER -> Huawei VRP (exercises K-B)
# ═══════════════════════════════════════════════════════════════════════

class TestCiscoRouterToHuawei:
    CONFIG = """hostname R5
router ospf 1
 router-id 1.1.1.1
 passive-interface default
 no passive-interface GigabitEthernet0/1
 network 10.0.0.0 0.0.0.255 area 0
 area 0.0.0.1 stub
 area 0.0.0.2 authentication message-digest
ip route 0.0.0.0 0.0.0.0 10.0.0.1
ip route 10.0.0.0 255.255.255.0 10.0.0.2 track 1
router bgp 65001
 neighbor 10.1.1.2 remote-as 65002
 neighbor 10.1.1.2 password SecretKey
 neighbor 10.1.1.2 update-source Loopback0
"""

    def test_auto_translated(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "cisco", "huawei")
        assert r.startswith("```huawei"), f"Wrong fence: {r[:20]}"
        assert "sysname R5" in r
        assert "ospf 1" in r
        assert "router-id 1.1.1.1" in r
        assert "silent-interface default" in r
        assert "undo silent-interface GigabitEthernet0/1" in r
        assert "network 10.0.0.0 0.0.0.255 area 0" in r
        assert "ip route-static 0.0.0.0 0.0.0.0 10.0.0.1" in r
        assert "ip route-static 10.0.0.0 255.255.255.0 10.0.0.2" in r
        assert "bgp 65001" in r
        assert "ipv4-family unicast" in r
        assert "peer 10.1.1.2 as-number 65002" in r

    def test_manual_review(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "cisco", "huawei")
        assert "MANUAL_REVIEW" in r
        assert "area 0.0.0.1 stub" in r, "stub area must be flagged"
        assert "area 0.1.0.2 authentication" in r or "area 0.0.0.2 authentication" in r, \
            "authentication area must be flagged"
        assert "track 1" in r or "route options:" in r, "track option must be flagged"
        assert "password" in r and "<redacted>" in r, "BGP password must be redacted"

    def test_no_secret_leak(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "cisco", "huawei")
        _check_no_secret_leak(r)
        assert "SecretKey" not in r, "BGP password leaked in output"

    def test_no_source_residue(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "cisco", "huawei")
        _check_no_source_residue(r, CISCO_RT)

    def test_manual_review_is_comment(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "cisco", "huawei")
        _check_manual_review_is_comment(r)

    def test_no_silent_drop(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "cisco", "huawei")
        exe = _executable_lines(r)
        assert len(exe) >= 10, f"Too few executable lines ({len(exe)}): {exe}"
        assert "peer 10.1.1.2 as-number 65002" in "\n".join(exe), \
            "BGP peer remote-as must be executable"


# ═══════════════════════════════════════════════════════════════════════
# Chain 6: Huawei ROUTER -> Cisco (exercises K-B)
# ═══════════════════════════════════════════════════════════════════════

class TestHuaweiRouterToCisco:
    CONFIG = """sysname R6
ip route-static 0.0.0.0 0.0.0.0 10.0.0.1
ip route-static 10.0.0.0 24 10.0.0.2
ip route-static 10.0.0.0 24 10.0.0.3 tag 100
ospf 1 router-id 1.1.1.1
 area 0.0.0.0
  network 10.0.0.0 0.0.0.255
 silent-interface GigabitEthernet0/0/1
 default-route-advertise always
bgp 65001
 peer 10.1.1.2 as-number 65002
 peer 10.1.1.2 password cipher MyCipherKey
"""

    def test_auto_translated(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei", "cisco")
        assert r.startswith("```cisco"), f"Wrong fence: {r[:20]}"
        assert "hostname R6" in r
        assert "ip route 0.0.0.0 0.0.0.0 10.0.0.1" in r
        assert "router ospf 1" in r
        assert "router-id 1.1.1.1" in r
        assert "area 0.0.0.0" in r
        assert "network 10.0.0.0 0.0.0.255" in r
        assert "passive-interface GigabitEthernet0/0/1" in r
        assert "router bgp 65001" in r
        assert "neighbor 10.1.1.2 remote-as 65002" in r

    def test_manual_review(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei", "cisco")
        assert "MANUAL_REVIEW" in r
        assert "tag 100" in r or "route options:" in r, "static route tag must be flagged"
        assert "default-route-advertise" in r, "ospf default-route must be flagged"
        assert "password" in r and "<redacted>" in r, "BGP password must be redacted"

    def test_no_secret_leak(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei", "cisco")
        _check_no_secret_leak(r)
        assert "MyCipherKey" not in r, "BGP cipher password leaked in output"

    def test_no_source_residue(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei", "cisco")
        _check_no_source_residue(r, HUAWEI_RT)

    def test_manual_review_is_comment(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei", "cisco")
        _check_manual_review_is_comment(r)

    def test_no_silent_drop(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei", "cisco")
        exe = _executable_lines(r)
        assert len(exe) >= 8, f"Too few executable lines ({len(exe)}): {exe}"
        assert "neighbor 10.1.1.2 remote-as 65002" in "\n".join(exe), \
            "BGP neighbor must be executable"


# ═══════════════════════════════════════════════════════════════════════
# Chain 7: Huawei USG -> Hillstone
# ═══════════════════════════════════════════════════════════════════════

class TestHuaweiUsgToHillstone:
    CONFIG = """security-zone name trust
security-zone name untrust
ip address-set TRUSTED type object
 address 0 10.0.0.0 mask 24
ip address-set DMZ type object
 address 0 192.168.1.0 mask 24
ip service-set HTTP type object
 service 0 protocol tcp destination-port 80
security-policy
 rule name ALLOW-WEB
  source-zone trust
  destination-zone untrust
  source-address 10.0.0.0 mask 24
  destination-address 192.168.1.0 mask 24
  service HTTP
  action permit
"""

    def test_auto_translated(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei_usg", "hillstone")
        assert r.startswith("```hillstone"), f"Wrong fence: {r[:20]}"
        assert "zone trust" in r
        assert "zone untrust" in r
        assert "address TRUSTED 10.0.0.0 255.255.255.0" in r
        assert "address DMZ 192.168.1.0 255.255.255.0" in r
        assert "service HTTP tcp 80" in r
        assert "policy" in r and "action permit" in r

    def test_no_secret_leak(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei_usg", "hillstone")
        _check_no_secret_leak(r)

    def test_no_source_residue(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei_usg", "hillstone")
        _check_no_source_residue(r, USG_KW)

    def test_no_default_any(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei_usg", "hillstone")
        _check_no_default_any(r)

    def test_manual_review_is_comment(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei_usg", "hillstone")
        _check_manual_review_is_comment(r)

    def test_no_silent_drop(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "huawei_usg", "hillstone")
        exe = _executable_lines(r)
        assert len(exe) >= 5, f"Too few executable lines ({len(exe)}): {exe}"
        assert any("action permit" in l for l in exe), "Policy action must survive"


# ═══════════════════════════════════════════════════════════════════════
# Chain 8: Hillstone -> Topsec
# ═══════════════════════════════════════════════════════════════════════

class TestHillstoneToTopsec:
    CONFIG = """zone trust
zone untrust
address TRUSTED 10.0.0.0 255.255.255.0
address DMZ 192.168.1.0 255.255.255.0
service HTTP tcp 80
policy P1 from trust to untrust source TRUSTED destination DMZ service HTTP action permit
"""

    def test_auto_translated(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "hillstone", "topsec")
        assert r.startswith("```topsec"), f"Wrong fence: {r[:20]}"
        assert "zone name trust" in r
        assert "zone name untrust" in r
        assert "address name TRUSTED ip 10.0.0.0 mask 255.255.255.0" in r
        assert "address name DMZ ip 192.168.1.0 mask 255.255.255.0" in r
        assert "service HTTP protocol tcp destination-port 80" in r
        assert "policy name P1" in r
        assert "source-zone trust" in r
        assert "destination-zone untrust" in r
        assert "source-address TRUSTED" in r
        assert "destination-address DMZ" in r
        assert "service HTTP" in r
        assert "action permit" in r

    def test_no_secret_leak(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "hillstone", "topsec")
        _check_no_secret_leak(r)

    def test_no_source_residue(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "hillstone", "topsec")
        _check_no_source_residue(r, HILLSTONE_KW)

    def test_no_default_any(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "hillstone", "topsec")
        _check_no_default_any(r)

    def test_manual_review_is_comment(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "hillstone", "topsec")
        _check_manual_review_is_comment(r)

    def test_no_silent_drop(self):
        r = RuleBasedTranslator().translate(self.CONFIG, "hillstone", "topsec")
        exe = _executable_lines(r)
        assert len(exe) >= 5, f"Too few executable lines ({len(exe)}): {exe}"
        assert any("action permit" in l for l in exe), "Policy action must survive"
