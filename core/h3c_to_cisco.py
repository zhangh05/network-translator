# -*- coding: utf-8 -*-
"""Dedicated H3C Comware → Cisco IOS config translator (block-level)."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


CIDR_TO_MASK = {
    0: "0.0.0.0", 1: "128.0.0.0", 2: "192.0.0.0", 3: "224.0.0.0",
    4: "240.0.0.0", 5: "248.0.0.0", 6: "252.0.0.0", 7: "254.0.0.0",
    8: "255.0.0.0", 9: "255.128.0.0", 10: "255.192.0.0", 11: "255.224.0.0",
    12: "255.240.0.0", 13: "255.248.0.0", 14: "255.252.0.0", 15: "255.254.0.0",
    16: "255.255.0.0", 17: "255.255.128.0", 18: "255.255.192.0", 19: "255.255.224.0",
    20: "255.255.240.0", 21: "255.255.248.0", 22: "255.255.252.0", 23: "255.255.254.0",
    24: "255.255.255.0", 25: "255.255.255.128", 26: "255.255.255.192", 27: "255.255.255.224",
    28: "255.255.255.240", 29: "255.255.255.248", 30: "255.255.255.252",
    31: "255.255.255.254", 32: "255.255.255.255",
}


def cidr_to_mask(length: int) -> str:
    return CIDR_TO_MASK.get(length, f"255.255.255.{255 & ~((1 << (32 - length)) - 1)}")


def _convert_vlan_range(vlan_str: str) -> str:
    parts = vlan_str.split()
    result = []
    i = 0
    while i < len(parts):
        p = parts[i]
        if p.lower() == "to" and i > 0 and i + 1 < len(parts):
            start = result.pop()
            result.append(f"{start}-{parts[i + 1]}")
            i += 2
        else:
            result.append(p)
            i += 1
    return ",".join(result)


def _cidr_to_netmask(prefix: str) -> str:
    try:
        n = int(prefix)
        return cidr_to_mask(n)
    except (ValueError, TypeError):
        return prefix


def _h3c_wildcard_to_cisco_mask(wildcard: str) -> str:
    try:
        parts = [int(x) for x in wildcard.split(".")]
        mask = [(255 - p) for p in parts]
        return ".".join(str(m) for m in mask)
    except (ValueError, TypeError):
        return wildcard


H3C_FORBIDDEN_IN_CISCO = [
    "Vlan-interface", "Bridge-Aggregation", "vrrp vrid",
    "packet-filter", "port link-mode", "port link-type",
    "port trunk permit", "port link-aggregation group",
    "ip route-static", "acl number", "hwtacacs scheme",
    "local-user", "snmp-agent", "ntp-service",
    "undo silent-interface", "authentication-mode scheme",
    "user-role", "info-center", "sysname",
    "return", "irf mode", "security-zone",
    "security-policy", "route-policy", "ip ip-prefix",
    "import-route", "port default vlan",
    "link-aggregation mode",
    "stp region-configuration", "stp instance",
    "stp global enable", "stp root",
    "domain ", "role name",
    "user-group", "password hash",
    "service-type", "authorization-attribute",
    "undo ssl", "undo info-center",
    "arp ip-conflict",
    "arp user-ip-conflict", "scheduler logfile",
    "security-enhanced", "burst-mode",
    "dldp global", "lldp global",
    "forward-path-detection", "system-working-mode",
    "ip unreachables", "ip ttl-expires",
    "ftth", "line class",
    "line aux",
    "protocol inbound",
    "idle-timeout",
    "clock timezone",
    "ip https",
    "telnet server",
    "webui-login",
    "super authentication",
]


def detect_h3c_residue(config_text: str) -> List[Dict]:
    hits = []
    lines = config_text.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("!"):
            continue
        lower = stripped.lower()
        for token in H3C_FORBIDDEN_IN_CISCO:
            if token.lower() in lower:
                start = max(0, i - 1)
                end = min(len(lines), i + 2)
                context = " ".join(lines[start:end]).strip()
                hits.append({
                    "token": token,
                    "matched_text": token,
                    "context": context[:80],
                    "severity": "high",
                })
    return hits


class H3CToCiscoTranslator:
    """Block-level H3C Comware to Cisco IOS configuration translator.

    Produces production-quality translations with MANUAL_REVIEW markers
    where semantic equivalence cannot be guaranteed.
    """

    def translate(self, config_text: str, to_vendor: str = "cisco") -> str:
        if not config_text:
            return ""
        to_vendor = to_vendor.lower()
        lines = [l.rstrip() for l in config_text.splitlines()]
        blocks = self._chunk_blocks(lines)
        output = []
        for block in blocks:
            translated = self._translate_block(block)
            if translated and translated.strip():
                output.append(translated)
        return self._wrap("\n".join(output), to_vendor)

    def _wrap(self, body: str, vendor: str) -> str:
        return f"```{vendor}\n{body.strip()}\n```"

    def translate_plain(self, config_text: str) -> str:
        """Translate without markdown fence wrapping."""
        if not config_text:
            return ""
        lines = [l.rstrip() for l in config_text.splitlines()]
        blocks = self._chunk_blocks(lines)
        output = []
        for block in blocks:
            translated = self._translate_block(block)
            if translated and translated.strip():
                output.append(translated)
        return "\n".join(output).strip()

    def _chunk_blocks(self, lines: List[str]) -> List[Dict]:
        blocks: List[Dict] = []
        current_block: Optional[Dict] = None

        def _flush():
            nonlocal current_block
            if current_block is not None:
                blocks.append(current_block)
            current_block = None

        for raw_line in lines:
            stripped = raw_line.strip()
            if not stripped or stripped == "return":
                continue
            if stripped in ("!", "#"):
                _flush()
                continue
            is_child = raw_line[:1].isspace()
            lower = stripped.lower()
            if is_child and current_block is not None:
                current_block.setdefault("body", []).append(stripped)
                continue
            _flush()
            type_key = self._detect_block_type(stripped, lower)
            current_block = {
                "type": type_key,
                "header": stripped,
                "body": [],
            }

        _flush()
        return blocks

    def _detect_block_type(self, header: str, lower: str) -> str:
        if re.match(r"^vlan\s+\d+", lower):
            return "vlan"
        if re.match(r"^interface\s+vlan-interface", lower):
            return "svi"
        if re.match(r"^interface\s+bridge-aggregation", lower):
            return "bridge_aggregation"
        if re.match(r"^interface\s+", lower):
            return "interface"
        if re.match(r"^ospf\s+\d+", lower):
            return "ospf"
        if re.match(r"^acl\s+number\s+\d+", lower):
            return "acl"
        if re.match(r"^ip\s+route-static", lower):
            return "static_route"
        if re.match(r"^snmp-agent", lower):
            return "system"
        if re.match(r"^ntp-service", lower):
            return "system"
        if re.match(r"^info-center", lower):
            return "system"
        if re.match(r"^ssh\s+server", lower):
            return "system"
        if re.match(r"^hwtacacs\s+scheme", lower):
            return "aaa"
        if re.match(r"^local-user", lower):
            return "aaa"
        if re.match(r"^domain\s+", lower):
            return "aaa"
        if re.match(r"^stp\s+", lower):
            return "stp"
        if re.match(r"^lldp", lower):
            return "system"
        if re.match(r"^dldp", lower):
            return "system"
        if re.match(r"^ip\s+unreachables", lower):
            return "system"
        if re.match(r"^ip\s+ttl-expires", lower):
            return "system"
        if re.match(r"^ip\s+https", lower):
            return "system"
        if re.match(r"^telnet", lower):
            return "system"
        if re.match(r"^line\s+", lower):
            return "line"
        if re.match(r"^role\s+", lower):
            return "aaa"
        if re.match(r"^user-group", lower):
            return "aaa"
        if re.match(r"^undo\s+", lower):
            return "system"
        if re.match(r"^sysname", lower):
            return "system"
        if re.match(r"^clock\s+", lower):
            return "system"
        if re.match(r"^irf\s+", lower):
            return "irf"
        if re.match(r"^forward-path-detection", lower):
            return "irf"
        if re.match(r"^burst-mode", lower):
            return "system"
        if re.match(r"^system-working-mode", lower):
            return "system"
        if re.match(r"^ip\s+unreachables", lower):
            return "system"
        if re.match(r"^ip\s+ttl-expires", lower):
            return "system"
        if re.match(r"^scheduler\s+", lower):
            return "system"
        if re.match(r"^security-enhanced", lower):
            return "system"
        if re.match(r"^arp\s+", lower):
            return "system"
        if re.match(r"^ftth", lower):
            return "system"
        if re.match(r"^return", lower):
            return "system"
        return "unknown"

    def _translate_block(self, block: Dict) -> str:
        handler = {
            "vlan": self._translate_vlan_block,
            "svi": self._translate_svi_block,
            "interface": self._translate_interface_block,
            "bridge_aggregation": self._translate_bridge_aggregation_block,
            "ospf": self._translate_ospf_block,
            "acl": self._translate_acl_block,
            "static_route": self._translate_static_route_block,
            "system": self._translate_system_block,
            "aaa": self._translate_aaa_block,
            "stp": self._translate_stp_block,
            "line": self._translate_line_block,
            "irf": lambda b: "",
            "unknown": self._translate_unknown_block,
        }
        h = handler.get(block["type"], self._translate_unknown_block)
        try:
            return h(block)
        except Exception:
            return f"! ERROR translating block: {block.get('header', '?')}"

    # ── VLAN Block ──
    def _translate_vlan_block(self, block: Dict) -> str:
        header = block["header"]
        out = [header]
        for line in block.get("body", []):
            lower = line.strip().lower()
            if lower.startswith("name "):
                out.append(f" name {line.split(maxsplit=1)[1]}")
            elif lower.startswith("description "):
                out.append(f" name {line.split(maxsplit=1)[1]}")
            else:
                out.append(line)
        return "\n".join(out)

    # ── SVI Block (Vlan-interface → Vlan) ──
    def _translate_svi_block(self, block: Dict) -> str:
        header = block["header"]
        m = re.match(r"interface\s+Vlan-interface(\d+)", header, re.IGNORECASE)
        if not m:
            return f"! {header}"
        vlan_id = m.group(1)
        out = [f"interface Vlan{vlan_id}"]
        vrrp_blocks = {}
        packet_filter = None
        has_ip = False
        for line in block.get("body", []):
            lower = line.strip().lower()
            if lower.startswith("description "):
                out.append(f" {line.strip()}")
            elif lower.startswith("ip address "):
                has_ip = True
                out.append(f" {line.strip()}")
            elif lower.startswith("ospf network-type p2p"):
                out.append(" ip ospf network point-to-point")
            elif lower.startswith("ospf network-type"):
                m2 = re.match(r"ospf\s+network-type\s+(\S+)", line.strip(), re.IGNORECASE)
                if m2:
                    out.append(f" ip ospf network {m2.group(1)}")
            elif lower.startswith("vrrp vrid"):
                m2 = re.match(r"vrrp\s+vrid\s+(\d+)\s+virtual-ip\s+(\S+)", line.strip(), re.IGNORECASE)
                if m2:
                    vrid = m2.group(1)
                    vrrp_blocks.setdefault(vrid, {})["ip"] = m2.group(2)
                    continue
                m2 = re.match(r"vrrp\s+vrid\s+(\d+)\s+priority\s+(\d+)", line.strip(), re.IGNORECASE)
                if m2:
                    vrid = m2.group(1)
                    vrrp_blocks.setdefault(vrid, {})["priority"] = m2.group(2)
                    continue
                out.append(f" ! unparsed VRRP: {line.strip()}")
            elif lower.startswith("packet-filter "):
                m2 = re.match(r"packet-filter\s+(\d+)\s+(inbound|outbound)", line.strip(), re.IGNORECASE)
                if m2:
                    acl_num = m2.group(1)
                    direction = "in" if m2.group(2).lower() == "inbound" else "out"
                    packet_filter = (acl_num, direction)
                else:
                    out.append(f" ! WARNING: unparsed packet-filter: {line.strip()}")
            else:
                out.append(f" {line.strip()}")
        for vrid, data in sorted(vrrp_blocks.items()):
            vip = data.get("ip", "")
            out.append(f" vrrp {vrid} ip {vip}" if vip else "")
            if "priority" in data:
                out.append(f" vrrp {vrid} priority {data['priority']}")
        if packet_filter:
            acl_num, direction = packet_filter
            out.append(f" ip access-group {acl_num} {direction}")
        return "\n".join(out)

    # ── Physical / Non-special Interface Block ──
    def _translate_interface_block(self, block: Dict) -> str:
        header = block["header"]
        out = [header]
        for line in block.get("body", []):
            lower = line.strip().lower()
            if lower.startswith("port link-mode bridge"):
                continue
            if lower.startswith("port link-type trunk"):
                out.append(" switchport mode trunk")
            elif lower.startswith("port link-type access"):
                out.append(" switchport mode access")
            elif lower.startswith("port trunk permit vlan "):
                rest = line.strip()[len("port trunk permit vlan "):]
                out.append(f" switchport trunk allowed vlan {_convert_vlan_range(rest)}")
            elif lower.startswith("port access vlan "):
                vlan_id = line.strip().split()[-1]
                out.append(" switchport mode access")
                out.append(f" switchport access vlan {vlan_id}")
            elif lower.startswith("port link-aggregation group "):
                group = line.strip().split()[-1]
                out.append(f" channel-group {group} mode active")
            elif lower.startswith("port default vlan "):
                rest = line.strip()[len("port default vlan "):]
                out.append(f" switchport access vlan {rest}")
            elif lower.startswith("link-aggregation mode dynamic"):
                continue
            elif lower.startswith("link-aggregation mode "):
                continue
            elif lower.startswith("description "):
                out.append(f" {line.strip()}")
            elif lower.startswith("ip address "):
                out.append(f" {line.strip()}")
            elif lower.startswith("vrrp vrid"):
                m2 = re.match(r"vrrp\s+vrid\s+(\d+)\s+virtual-ip\s+(\S+)", line.strip(), re.IGNORECASE)
                if m2:
                    out.append(f" vrrp {m2.group(1)} ip {m2.group(2)}")
                else:
                    m3 = re.match(r"vrrp\s+vrid\s+(\d+)\s+priority\s+(\d+)", line.strip(), re.IGNORECASE)
                    if m3:
                        out.append(f" vrrp {m3.group(1)} priority {m3.group(2)}")
                    else:
                        out.append(f" ! WARNING: unparsed VRRP: {line.strip()}")
            elif lower.startswith("packet-filter "):
                m2 = re.match(r"packet-filter\s+(\d+)\s+(inbound|outbound)", line.strip(), re.IGNORECASE)
                if m2:
                    direction = "in" if m2.group(2).lower() == "inbound" else "out"
                    out.append(f" ip access-group {m2.group(1)} {direction}")
            elif lower.startswith("ospf network-type p2p"):
                out.append(" ip ospf network point-to-point")
            elif lower.startswith("ospf network-type"):
                mp = re.match(r"ospf\s+network-type\s+(\S+)", line.strip(), re.IGNORECASE)
                if mp:
                    out.append(f" ip ospf network {mp.group(1)}")
            elif lower.startswith("vlan dot1q"):
                continue
            elif lower.startswith("stp edged-port enable"):
                out.append(" spanning-tree portfast")
            elif lower.startswith("stp edged-port"):
                out.append(" spanning-tree portfast")
            elif lower.startswith("undo shutdown"):
                out.append(" no shutdown")
            elif lower.startswith("shutdown"):
                out.append(" shutdown")
            else:
                out.append(f" {line.strip()}")
        return "\n".join(out)

    # ── Bridge-Aggregation → Port-channel ──
    def _translate_bridge_aggregation_block(self, block: Dict) -> str:
        header = block["header"]
        m = re.match(r"interface\s+Bridge-Aggregation(\d+)", header, re.IGNORECASE)
        if not m:
            return f"! {header}"
        group = m.group(1)
        out = [f"interface Port-channel{group}"]
        for line in block.get("body", []):
            lower = line.strip().lower()
            if lower.startswith("port link-type trunk"):
                out.append(" switchport mode trunk")
            elif lower.startswith("port trunk permit vlan "):
                rest = line.strip()[len("port trunk permit vlan "):]
                out.append(f" switchport trunk allowed vlan {_convert_vlan_range(rest)}")
            elif lower.startswith("port link-type access"):
                out.append(" switchport mode access")
            elif lower.startswith("port access vlan "):
                vlan_id = line.strip().split()[-1]
                out.append(f" switchport access vlan {vlan_id}")
            elif lower.startswith("description "):
                out.append(f" {line.strip()}")
            elif lower.startswith("ip address "):
                out.append(f" {line.strip()}")
            elif lower.startswith("link-aggregation mode dynamic"):
                continue
            elif lower.startswith("link-aggregation mode "):
                continue
            elif lower.startswith("port link-mode bridge"):
                continue
            else:
                out.append(f" {line.strip()}")
        return "\n".join(out)

    # ── OSPF Block ──
    def _translate_ospf_block(self, block: Dict) -> str:
        header = block["header"]
        m = re.match(r"ospf\s+(\S+)\s+router-id\s+(\S+)", header, re.IGNORECASE)
        if m:
            out = [f"router ospf {m.group(1)}", f" router-id {m.group(2)}"]
        else:
            m2 = re.match(r"ospf\s+(\S+)", header, re.IGNORECASE)
            if m2:
                out = [f"router ospf {m2.group(1)}"]
            else:
                out = [f"! {header}"]

        seen_silent_all = False
        for line in block.get("body", []):
            lower = line.strip().lower()
            if lower.startswith("import-route static"):
                out.append(" redistribute static")
            elif lower.startswith("import-route "):
                rest = line.strip()[len("import-route "):]
                out.append(f" redistribute {rest}")
            elif lower.startswith("silent-interface all"):
                seen_silent_all = True
                out.append(" passive-interface default")
            elif lower.startswith("silent-interface"):
                rest = line.strip()[len("silent-interface "):]
                iface = rest.replace("Vlan-interface", "Vlan")
                out.append(f" passive-interface {iface}")
            elif lower.startswith("undo silent-interface "):
                rest = line.strip()[len("undo silent-interface "):]
                iface = rest.replace("Vlan-interface", "Vlan")
                if seen_silent_all:
                    out.append(f" no passive-interface {iface}")
                else:
                    out.append(f" no passive-interface {iface}")
            elif lower.startswith("area "):
                m_area = re.match(r"area\s+(\S+)", line.strip(), re.IGNORECASE)
                if m_area:
                    area_id = m_area.group(1)
                    out.append(f" area {area_id}")
            elif lower.startswith("network "):
                m_net = re.match(r"network\s+(\S+)\s+(\S+)", line.strip(), re.IGNORECASE)
                if m_net:
                    subnet = m_net.group(1)
                    wildcard = m_net.group(2)
                    out.append(f" network {subnet} {wildcard} area 0")
            elif lower.startswith("default-route-advertise"):
                out.append(" default-information originate")
            elif lower.startswith("preference") or lower.startswith("pref"):
                out.append(f" {line.strip()}")
            elif lower.startswith("description "):
                out.append(f" {line.strip()}")
            elif lower.startswith("ospf network-type"):
                continue
            elif lower.startswith("vrrp"):
                continue
            else:
                out.append(f" {line.strip()}")

        return "\n".join(out)

    # ── ACL Block ──
    def _translate_acl_block(self, block: Dict) -> str:
        header = block["header"]
        m = re.match(r"acl\s+number\s+(\d+)", header, re.IGNORECASE)
        if not m:
            return f"! {header}"
        acl_num = m.group(1)
        try:
            num = int(acl_num)
        except ValueError:
            num = 0
        is_standard = 2000 <= num <= 2999
        acl_type = "standard" if is_standard else "extended"
        out = [f"ip access-list {acl_type} {acl_num}"]
        for line in block.get("body", []):
            lower = line.strip().lower()
            m_rule = re.match(r"rule\s+(\d+)?\s*(permit|deny)\s+(.+)", lower)
            if not m_rule:
                continue
            rule_id = m_rule.group(1) or ""
            action = m_rule.group(2)
            rest = m_rule.group(3)
            seq = f" {rule_id}" if rule_id else ""
            translated = self._translate_acl_rule(action, rest, is_standard)
            out.append(f"{seq} {translated}")
        return "\n".join(out)

    def _translate_acl_rule(self, action: str, rest: str, is_standard: bool = False) -> str:
        rest = rest.strip()
        parts = rest.split()
        if not parts:
            if is_standard:
                return f"{action} any"
            return f"{action} ip any any"

        first = parts[0].lower()
        if first in ("ip", "tcp", "udp", "icmp", "igmp", "ospf", "vrrp", "pim", "rsvp"):
            protocol = first
            remaining = " ".join(parts[1:]) if len(parts) > 1 else ""
            if protocol == "ip" and not remaining:
                if is_standard:
                    return f"{action} any"
                return f"{action} ip any any"
        else:
            protocol = "ip"
            remaining = rest

        src_ip = "any"
        src_wc = None
        dst_ip = "any"
        dst_wc = None

        src_m = re.match(r"source\s+(\S+)(?:\s+(\S+))?", remaining, re.IGNORECASE)
        if src_m:
            src_ip = src_m.group(1)
            src_wc = src_m.group(2)
            remaining = remaining[src_m.end():].strip()
            if remaining.lower().startswith("destination"):
                remaining = remaining[len("destination"):].strip()

        if remaining and remaining.strip():
            tokens = remaining.strip().split()
            if tokens:
                dst_ip = tokens[0]
                if len(tokens) > 1:
                    dst_wc = tokens[1]

        def _fmt_ip(v: str) -> str:
            if not v or v in ("any", "0"):
                return "any"
            return f"host {v}" if "." in v else v

        src_str = _fmt_ip(src_ip)
        if src_wc and src_wc != "0":
            src_str = f"{src_ip} {src_wc}"

        if is_standard:
            return f"{action} {src_str}"

        if protocol == "ip":
            proto_str = "ip"
        else:
            proto_str = protocol

        dst_str = _fmt_ip(dst_ip)
        if dst_wc and dst_wc != "0":
            dst_str = f"{dst_ip} {dst_wc}"

        return f"{action} {proto_str} {src_str} {dst_str}"

    # ── Static Route ──
    def _translate_static_route_block(self, block: Dict) -> str:
        def _translate_one(line):
            m = re.match(r"ip\s+route-static\s+(\S+)\s+(\S+)\s+(\S+)", line, re.IGNORECASE)
            if not m:
                return None
            prefix = m.group(1)
            length_or_mask = m.group(2)
            nexthop = m.group(3)
            try:
                cidr = int(length_or_mask)
                mask = _cidr_to_netmask(length_or_mask)
            except ValueError:
                mask = length_or_mask
            return f"ip route {prefix} {mask} {nexthop}"

        out = []
        header = block["header"]
        translated = _translate_one(header)
        if translated:
            out.append(translated)
        for line in block.get("body", []):
            translated = _translate_one(line)
            if translated:
                out.append(translated)
        if not out:
            return f"! {header}"
        return "\n".join(out)

    # ── System Commands ──
    def _translate_system_block(self, block: Dict) -> str:
        header = block["header"]
        lower = header.lower()
        if lower.startswith("sysname "):
            return f"hostname {header.split(maxsplit=1)[1]}"
        if lower.startswith("snmp-agent"):
            cmd = header.strip()
            if "community" in lower:
                m = re.match(r"snmp-agent\s+community\s+(read|write)\s+(\S+)\s+acl\s+(\d+)", lower)
                if m:
                    mode = "RO" if m.group(1) == "read" else "RW"
                    return f"snmp-server community {m.group(2)} {mode} {m.group(3)}"
                m = re.match(r"snmp-agent\s+community\s+(read|write)\s+(\S+)", lower)
                if m:
                    mode = "RO" if m.group(1) == "read" else "RW"
                    return f"snmp-server community {m.group(2)} {mode}"
            if "sys-info" in lower or "version" in lower:
                return f"! {header} // MANUAL_REVIEW: SNMP version config"
            if "local-engineid" in lower:
                return f"! {header} // MANUAL_REVIEW: SNMP engine ID"
            return f"! {header} // MANUAL_REVIEW: SNMP config"
        if lower.startswith("ntp-service"):
            m = re.match(r"ntp-service\s+unicast-server\s+(\S+)", lower)
            if m:
                return f"ntp server {m.group(1)}"
            return f"! {header} // MANUAL_REVIEW: NTP config"
        if lower.startswith("ssh server enable"):
            return "ip ssh version 2"
        if lower.startswith("info-center"):
            m = re.match(r"info-center\s+loghost\s+(\S+)(?:\s+source\s+(\S+))?", lower)
            if m:
                host = m.group(1)
                src = m.group(2)
                line = f"logging host {host}"
                if src:
                    line += f" source-interface {src.replace('LoopBack', 'Loopback')}"
                return line
            m2 = re.match(r"info-center\s+logfile", lower)
            if m2:
                return ""
            return f"! {header} // MANUAL_REVIEW: logging config"
        if lower.startswith("clock timezone"):
            return f"! {header} // MANUAL_REVIEW: clock timezone"
        if lower.startswith("lldp global enable"):
            return "lldp run"
        if lower.startswith("dldp global enable"):
            return ""
        if lower.startswith("undo info-center"):
            return ""
        if lower.startswith("undo ssl"):
            return f"! {header} // MANUAL_REVIEW: SSL config"
        if lower.startswith("undo "):
            return f"! {header} // MANUAL_REVIEW"
        if lower.startswith("arp "):
            return f"! {header} // MANUAL_REVIEW: ARP config"
        if lower.startswith("ip unreachables"):
            return "ip icmp redirect\nip icmp unreachable"
        if lower.startswith("ip ttl-expires"):
            return ""
        if lower.startswith("scheduler "):
            return f"! {header}"
        if lower.startswith("security-enhanced"):
            return ""
        if lower.startswith("burst-mode"):
            return ""
        if lower.startswith("system-working-mode"):
            return ""
        if lower.startswith("forward-path-detection"):
            return ""
        if lower.startswith("irf "):
            return ""
        if lower.startswith("ip https"):
            return f"! {header} // MANUAL_REVIEW: HTTPS config"
        if lower.startswith("telnet server"):
            return f"! {header} // MANUAL_REVIEW: telnet config"
        if lower.startswith("webui-login"):
            return ""
        if lower.startswith("super authentication"):
            return ""
        if lower.startswith("ftth"):
            return ""
        if lower.startswith("return"):
            return ""
        return f"! {header} // MANUAL_REVIEW"

    # ── AAA (hwtacacs/local-user/domain) ──
    def _translate_aaa_block(self, block: Dict) -> str:
        header = block["header"]
        lower = header.lower()
        if lower.startswith("hwtacacs scheme"):
            name = header.split()[-1] if len(header.split()) >= 3 else ""
            lines = [f"! HWTACACS scheme '{name}' → AAA server group (MANUAL_REVIEW)"]
            for line in block.get("body", []):
                h = line.strip()
                lines.append(f"!   {h}")
            lines.append("! MANUAL_REVIEW: Cisco AAA config needs: ")
            lines.append("!   aaa new-model")
            lines.append(f"!   tacacs server {name}")
            if name:
                lines.append(f"!   aaa group server tacacs+ {name}")
            return "\n".join(lines)
        if lower.startswith("local-user"):
            name = header.split()[1] if len(header.split()) >= 2 else ""
            lines = [f"! local-user '{name}' → MANUAL_REVIEW"]
            for line in block.get("body", []):
                lines.append(f"!   {line.strip()}")
            lines.append("! Cisco equivalent: username <name> privilege <n> secret <password>")
            return "\n".join(lines)
        if lower.startswith("domain "):
            name = header.split()[-1] if len(header.split()) >= 2 else ""
            lines = [f"! domain '{name}' → MANUAL_REVIEW"]
            for line in block.get("body", []):
                lines.append(f"!   {line.strip()}")
            return "\n".join(lines)
        if lower.startswith("role name") or lower.startswith("user-group"):
            return f"! {header} → MANUAL_REVIEW (RBAC not directly translatable)"
        return f"! {header} → MANUAL_REVIEW"

    # ── STP Block ──
    def _translate_stp_block(self, block: Dict) -> str:
        header = block["header"]
        lower = header.lower()
        if lower.startswith("stp region-configuration"):
            out = ["spanning-tree mst configuration"]
            for line in block.get("body", []):
                l = line.strip().lower()
                if l.startswith("region-name "):
                    out.append(f" name {line.split(maxsplit=1)[1]}")
                elif l.startswith("instance "):
                    m = re.match(r"instance\s+(\d+)\s+vlan\s+(.+)", line.strip(), re.IGNORECASE)
                    if m:
                        vlans = _convert_vlan_range(m.group(2))
                        out.append(f" instance {m.group(1)} vlan {vlans}")
                elif l.startswith("active region-configuration"):
                    out.append(" exit")
                else:
                    out.append(f" {line.strip()}")
            return "\n".join(out)
        body = block.get("body", [])
        all_lines = [header] + body
        out = []
        for line in all_lines:
            l = line.strip().lower()
            if l.startswith("stp instance "):
                m = re.match(r"stp\s+instance\s+(\d+)\s+to\s+(\d+)\s+root\s+(primary|secondary)", l)
                if m:
                    out.append(f"spanning-tree mst {m.group(1)}-{m.group(2)} root {m.group(3)}")
                    continue
                m2 = re.match(r"stp\s+instance\s+(\d+)\s+root\s+(primary|secondary)", l)
                if m2:
                    out.append(f"spanning-tree mst {m2.group(1)} root {m2.group(2)}")
                    continue
            if l.startswith("stp global enable"):
                continue
            if l.startswith("stp "):
                rest = l[4:].strip()
                if rest:
                    out.append(f"spanning-tree {rest}")
            else:
                out.append(line)
        return "\n".join(out)

    # ── Line Block ──
    def _translate_line_block(self, block: Dict) -> str:
        header = block["header"]
        lower = header.lower()
        if lower.startswith("line vty"):
            m = re.match(r"line\s+vty\s+(\d+)\s+(\d+)", lower)
            if m:
                out = [f"line vty {m.group(1)} {m.group(2)}"]
            else:
                m2 = re.match(r"line\s+vty\s+(\d+)", lower)
                if m2:
                    out = [f"line vty {m2.group(1)}"]
                else:
                    out = ["line vty 0 4"]
            for line in block.get("body", []):
                l = line.strip().lower()
                if l.startswith("authentication-mode scheme"):
                    out.append(" login authentication default")
                elif l.startswith("user-role"):
                    continue
                elif l.startswith("protocol inbound ssh"):
                    out.append(" transport input ssh")
                elif l.startswith("idle-timeout"):
                    m = re.match(r"idle-timeout\s+(\d+)\s+(\d+)", l)
                    if m:
                        out.append(f" exec-timeout {int(m.group(1))} {int(m.group(2))}")
                    else:
                        out.append(f" exec-timeout 5 0")
                else:
                    out.append(f" {line.strip()}")
            return "\n".join(out)
        if lower.startswith("line class") or lower.startswith("line aux"):
            return f"! {header} // MANUAL_REVIEW"
        return f"! {header} // MANUAL_REVIEW"

    # ── Unknown Block ──
    def _translate_unknown_block(self, block: Dict) -> str:
        header = block["header"]
        lower = header.lower()
        for token in H3C_FORBIDDEN_IN_CISCO:
            if token.lower() in lower:
                return f"! {header} // MANUAL_REVIEW: H3C command, no Cisco equivalent"
        return f"! {header} // MANUAL_REVIEW"
