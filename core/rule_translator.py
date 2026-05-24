# -*- coding: utf-8 -*-
"""Deterministic rule-based fallback translator for common network commands."""

import re
from typing import List, Optional, Union


class RuleBasedTranslator:
    """Translate common network configuration lines without an LLM.

    This is intentionally conservative. It is a fallback for high-frequency
    primitives, not a replacement for the IR/LLM translation path.
    """

    def translate(self, config_text: str, from_vendor: str, to_vendor: str) -> str:
        from_vendor = (from_vendor or "unknown").lower()
        to_vendor = (to_vendor or "unknown").lower()
        if not config_text or not to_vendor:
            return ""
        if from_vendor == to_vendor:
            return self._wrap(config_text.strip(), to_vendor)

        output: List[str] = []
        state = {"acl": None, "in_bgp": False}

        for raw in config_text.splitlines():
            line = raw.rstrip()
            if not line.strip() or line.strip() in ("!", "#"):
                continue
            translated = self._translate_line(line, from_vendor, to_vendor, state)
            if translated is None:
                continue
            if isinstance(translated, list):
                output.extend(translated)
            else:
                output.append(translated)

        # EOF flush: emit MANUAL_REVIEW for any incomplete multi-line block
        pending = self._flush_pending_state(state, to_vendor)
        if pending:
            output.extend(pending)

        if not output:
            return ""
        return self._wrap("\n".join(output), to_vendor)

    def _wrap(self, body: str, vendor: str) -> str:
        return f"```{vendor}\n{body.strip()}\n```"

    def _translate_line(self, line: str, from_vendor: str, to_vendor: str, state: dict):
        stripped = line.strip()
        indent = line[: len(line) - len(line.lstrip())]
        lower = stripped.lower()

        # Flush pending multi-line block at line boundary before processing
        flush_output = self._check_flush_secpol_at_line_boundary(indent, state)

        if to_vendor == "huawei":
            rv = self._to_huawei(stripped, lower, indent, from_vendor, state)
        elif to_vendor == "h3c":
            rv = self._to_h3c(stripped, lower, indent, from_vendor, state)
        elif to_vendor == "cisco":
            rv = self._to_cisco(stripped, lower, indent, from_vendor, state)
        elif to_vendor == "ruijie":
            rv = self._to_ruijie(stripped, lower, indent, from_vendor, state)
        elif to_vendor == "hillstone":
            rv = self._to_hillstone_firewall(stripped, lower, indent, from_vendor, state)
        elif to_vendor == "huawei_usg":
            rv = self._to_huawei_usg_firewall(stripped, lower, indent, from_vendor, state)
        elif to_vendor in ("topsec", "dptech"):
            rv = self._to_firewall_manual_review(stripped, indent, to_vendor, from_vendor)
        else:
            rv = line

        if flush_output:
            if rv is None:
                return flush_output
            if isinstance(rv, list):
                return flush_output + rv
            return flush_output + [rv]
        return rv

    def _to_huawei(self, stripped: str, lower: str, indent: str, from_vendor: str, state: dict):
        if lower.startswith("hostname "):
            return "sysname " + stripped.split(maxsplit=1)[1]
        if lower.startswith("sysname "):
            return stripped

        # VLAN: convert Cisco/Ruijie comma format, passthrough H3C/Huawei
        m = re.match(r"^vlan\s+(\S.*)", stripped, re.IGNORECASE)
        if m:
            vlan_val = m.group(1)
            if from_vendor in ("huawei", "h3c"):
                return stripped
            vlans = self._parse_vlan_list(vlan_val)
            if len(vlans) == 1:
                return f"vlan {vlans[0]}"
            return f"vlan batch {self._format_vlans_huawei_batch(vlans)}"

        # SVI: Cisco/Ruijie Vlan N -> Huawei Vlanif N
        m = re.match(r"^interface\s+Vlan(\d+)$", stripped, re.IGNORECASE)
        if m:
            return f"interface Vlanif{m.group(1)}"

        if lower.startswith("interface "):
            name = stripped.split(maxsplit=1)[1]
            name = self._normalize_interface_to_huawei(name)
            return "interface " + name
        if lower.startswith("description "):
            return indent + stripped
        if lower.startswith("ip address "):
            return indent + stripped
        if lower == "no shutdown":
            return indent + "undo shutdown"
        if lower == "shutdown":
            return indent + "shutdown"

        translated_switching = self._translate_switching_to_huawei(stripped, lower, indent, from_vendor)
        if translated_switching is not None:
            return translated_switching

        translated_routing = self._translate_routing_to_huawei(stripped, lower, indent, state)
        if translated_routing is not None:
            return translated_routing

        # VRF
        m = re.match(r"vrf\s+definition\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return f"ip vpn-instance {m.group(1)}"
        if lower.startswith("rd "):
            return indent + "route-distinguisher " + stripped.split(maxsplit=1)[1]
        if lower.startswith("route-target "):
            return indent + "vpn-target " + stripped.split(maxsplit=1)[1]
        if lower.startswith("route-distinguisher "):
            return indent + stripped
        if lower.startswith("vpn-target "):
            return indent + stripped

        translated_acl = self._translate_acl_to_huawei(stripped, lower, state)
        if translated_acl is not None:
            return translated_acl

        # Route-map / prefix-list -> MANUAL_REVIEW
        if lower.startswith(("route-map ", "route-policy ", "ip prefix-list ", "prefix-list ")):
            return indent + self._manual_review_comment(stripped, "huawei", indent)
        # Unknown SVI / VLAN commands -> MANUAL_REVIEW
        if lower.startswith(("spanning-tree ", "stp ", "bpduguard", "loopguard", "rootguard")):
            return indent + self._manual_review_comment(stripped, "huawei", indent)

        return stripped if from_vendor in ("h3c", "huawei") else indent + stripped

    def _translate_switching_to_huawei(self, stripped: str, lower: str, indent: str, from_vendor: str):
        if lower == "switchport trunk encapsulation dot1q":
            return None
        if lower == "switchport mode trunk":
            return indent + "port link-type trunk"
        if lower == "switchport mode access":
            return indent + "port link-type access"
        m = re.match(r"switchport\s+access\s+vlan\s+(.+)", lower)
        if m:
            return indent + "port default vlan " + self._normalize_vlan_list(m.group(1))
        m = re.match(r"switchport\s+trunk\s+(?:allowed|allow-pass)\s+vlan\s+(.+)", lower)
        if m:
            return indent + "port trunk allow-pass vlan " + self._normalize_vlan_list(m.group(1))
        m = re.match(r"port\s+trunk\s+permit\s+vlan\s+(.+)", lower)
        if m:
            return indent + "port trunk allow-pass vlan " + self._normalize_vlan_list(m.group(1))
        if lower in ("spanning-tree portfast", "stp edged-port"):
            return indent + "stp edged-port enable"
        if from_vendor in ("h3c", "huawei") and lower.startswith(
            ("port link-type ", "port default vlan ", "port trunk allow-pass vlan ", "stp edged-port enable")
        ):
            return indent + stripped
        m = re.match(r"(channel-group|eth-trunk|port-group|bridge-aggregation)\s+(\d+)(?:\s+mode\s+\S+)?", stripped, re.IGNORECASE)
        if m:
            return indent + f"eth-trunk {m.group(2)}"
        return None

    def _translate_routing_to_huawei(self, stripped: str, lower: str, indent: str, state: dict):
        # Static route
        m = re.match(r"ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$", stripped, re.IGNORECASE)
        if m:
            route = f"ip route-static {m.group(1)} {m.group(2)} {m.group(3)}"
            if m.group(4):
                return [route, f"# MANUAL_REVIEW route options: {m.group(4)}"]
            return route
        if lower.startswith("ip route-static "):
            m = re.match(r"ip route-static\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$", stripped, re.IGNORECASE)
            if m:
                route = f"ip route-static {m.group(1)} {m.group(2)} {m.group(3)}"
                if m.group(4):
                    return [route, f"# MANUAL_REVIEW route options: {m.group(4)}"]
                return route

        # OSPF
        m = re.match(r"router\s+ospf\s+(\S+)", lower)
        if m:
            state["in_bgp"] = False
            return "ospf " + m.group(1)
        m = re.match(r"ospf\s+(\S+)", lower)
        if m:
            state["in_bgp"] = False
            return stripped
        if lower.startswith("router-id "):
            return indent + stripped
        if lower.startswith("network ") and not state.get("in_bgp"):
            return indent + stripped
        if lower.startswith("passive-interface "):
            return indent + "silent-interface " + lower.split(maxsplit=1)[1]
        if lower.startswith("no passive-interface "):
            return indent + "undo silent-interface " + lower.split(maxsplit=2)[2]
        if lower == "passive-interface default":
            return indent + "silent-interface default"

        # BGP
        m = re.match(r"router\s+bgp\s+(\S+)", lower)
        if m:
            state["in_bgp"] = True
            return ["bgp " + m.group(1), " ipv4-family unicast"]
        m = re.match(r"bgp\s+(\S+)", lower)
        if m:
            state["in_bgp"] = True
            return stripped
        m = re.match(r"neighbor\s+(\S+)\s+remote-as\s+(\S+)", lower)
        if m:
            return f" peer {m.group(1)} as-number {m.group(2)}"
        m = re.match(r"peer\s+(\S+)\s+as-number\s+(\S+)", lower)
        if m:
            return stripped
        m = re.match(r"network\s+(\S+)\s+mask\s+(\S+)", lower)
        if m:
            return f" network {m.group(1)} {m.group(2)}"
        if lower.startswith("neighbor ") or lower.startswith(" peer "):
            return indent + self._manual_review_comment(stripped, "huawei", indent)
        if lower.startswith("ipv4-family unicast"):
            return None

    def _to_cisco(self, stripped: str, lower: str, indent: str, from_vendor: str, state: dict):
        if lower.startswith("sysname "):
            return "hostname " + stripped.split(maxsplit=1)[1]
        if lower.startswith("hostname "):
            return stripped
        m = re.match(r"vlan\s+batch\s+(.+)", stripped, re.IGNORECASE)
        if m:
            state["unsupported_interface"] = False
            vlans = self._parse_vlan_list(m.group(1))
            return "vlan " + self._format_vlans_cisco(vlans)
        m = re.match(r"^vlan\s+(\S.*)", stripped, re.IGNORECASE)
        if m:
            state["unsupported_interface"] = False
            vlans = self._parse_vlan_list(m.group(1))
            return "vlan " + self._format_vlans_cisco(vlans)
        # SVI
        m = re.match(r"^interface\s+Vlanif(\d+)$", stripped, re.IGNORECASE)
        if m:
            state["unsupported_interface"] = False
            return f"interface Vlan{m.group(1)}"
        m = re.match(r"^interface\s+Vlan-interface(\d+)$", stripped, re.IGNORECASE)
        if m:
            state["unsupported_interface"] = False
            return f"interface Vlan{m.group(1)}"
        if lower.startswith("interface "):
            name = stripped.split(maxsplit=1)[1]
            name = self._normalize_interface_to_cisco(name)
            if name is None:
                state["unsupported_interface"] = True
                return self._manual_review_comment(stripped, "cisco", indent)
            state["unsupported_interface"] = False
            return f"interface {name}"
        if state.get("unsupported_interface") and indent:
            return self._manual_review_comment(stripped, "cisco", indent)
        if lower.startswith("description "):
            return indent + stripped
        if lower.startswith("ip address ") and lower.endswith(" sub"):
            return indent + stripped[:-4] + " secondary"
        if lower.startswith("ip address "):
            return indent + stripped
        if lower == "undo shutdown":
            return indent + "no shutdown"
        if lower == "shutdown":
            return indent + "shutdown"
        # OSPF
        if lower.startswith("ospf ") and "router-id" in lower:
            m = re.match(r"ospf\s+(\S+)\s+router-id\s+(\S+)", lower)
            if m:
                return [f"router ospf {m.group(1)}", f" router-id {m.group(2)}"]
        if lower.startswith("ospf "):
            m = re.match(r"ospf\s+(\S+)", lower)
            return f"router ospf {m.group(1)}" if m else stripped
        if lower.startswith("area "):
            return indent + stripped
        if lower.startswith("network "):
            return indent + stripped
        if lower.startswith("router-id "):
            return indent + stripped
        if lower.startswith("silent-interface"):
            return indent + "passive-interface " + stripped.split(maxsplit=1)[1]
        # BGP
        if lower.startswith("bgp "):
            m = re.match(r"bgp\s+(\S+)", lower)
            if m:
                state["in_bgp"] = True
                return f"router bgp {m.group(1)}"
        m = re.match(r"peer\s+(\S+)\s+as-number\s+(\S+)", lower)
        if m:
            return f" neighbor {m.group(1)} remote-as {m.group(2)}"
        m = re.match(r"network\s+(\S+)\s+mask\s+(\S+)", lower)
        if m:
            return f" network {m.group(1)} {m.group(2)}"
        if lower.startswith("ipv4-family unicast"):
            return None
        # VRF
        m = re.match(r"vrf\s+definition\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return f"vrf definition {m.group(1)}"
        m = re.match(r"ip\s+vpn-instance\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return f"vrf definition {m.group(1)}"
        if lower.startswith("route-distinguisher "):
            return indent + "rd " + stripped.split(maxsplit=1)[1]
        if lower.startswith("vpn-target "):
            return indent + "route-target " + stripped.split(maxsplit=1)[1]

        m = re.match(r"ip route-static\s+vpn-instance\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return f"ip route vrf {m.group(1)} {m.group(2)} {m.group(3)} {m.group(4)}"
        m = re.match(r"ip route-static\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$", stripped, re.IGNORECASE)
        if m:
            route = f"ip route {m.group(1)} {m.group(2)} {m.group(3)}"
            if m.group(4):
                return [route, f"! MANUAL_REVIEW route options: {m.group(4)}"]
            return route

        if lower.startswith("port link-type trunk"):
            return indent + "switchport mode trunk"
        if lower.startswith("port link-type access"):
            return indent + "switchport mode access"
        m = re.match(r"port default vlan\s+(.+)", lower)
        if m:
            return indent + "switchport access vlan " + self._normalize_vlan_list(m.group(1))
        m = re.match(r"port trunk (allow-pass|permit) vlan\s+(.+)", lower)
        if m:
            return indent + "switchport trunk allowed vlan " + self._normalize_vlan_list_cisco(m.group(2))
        m = re.match(r"(eth-trunk|port link-aggregation group|bridge-aggregation)\s+(\d+)", lower)
        if m:
            return indent + f"channel-group {m.group(2)} mode active"
        m = re.match(r"port-group\s+(\d+)", lower)
        if m:
            return indent + f"channel-group {m.group(1)} mode active"
        if lower.startswith("stp edged-port"):
            return indent + "spanning-tree portfast"
        m = re.match(r"traffic-filter\s+(inbound|outbound)\s+acl(?:\s+name)?\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return indent + f"ip access-group {m.group(2)} {self._direction_to_cisco(m.group(1))}"
        m = re.match(r"traffic-policy\s+(\S+)\s+(inbound|outbound)", stripped, re.IGNORECASE)
        if m:
            return indent + f"service-policy {self._direction_to_cisco_qos(m.group(2))} {m.group(1)}"

        m = re.match(r"acl\s+number\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            state["acl"] = m.group(1)
            return f"ip access-list extended {state['acl']}"
        m = re.match(r"acl\s+name\s+(\S+)(?:\s+\S+)?", stripped, re.IGNORECASE)
        if m:
            state["acl"] = m.group(1)
            return f"ip access-list extended {state['acl']}"
        if lower.startswith("rule ") and state.get("acl"):
            return indent + self._translate_vrp_acl_rule_to_cisco(stripped)

        snmp = self._translate_huawei_snmp_to_cisco(stripped)
        if snmp is not None:
            return indent + snmp

        if lower.startswith(("route-map ", "route-policy ", "ip prefix-list ", "prefix-list ")):
            return indent + self._manual_review_comment(stripped, "cisco", indent)

        # Unknown spanning-tree / STP features -> MANUAL_REVIEW
        if lower.startswith(("spanning-tree ", "stp ", "bpduguard", "loopguard", "rootguard")):
            if not (lower.startswith("stp edged-port") or lower == "spanning-tree portfast"):
                return self._manual_review_comment(stripped, "cisco", indent)

        if from_vendor in ("huawei", "h3c"):
            return self._manual_review_comment(stripped, "cisco", indent)
        return stripped

    def _translate_acl_to_huawei(self, stripped: str, lower: str, state: dict):
        m = re.match(r"access-list\s+(\d+)\s+(permit|deny)\s+(\S+)\s+(.+)", lower)
        if not m:
            return None

        acl_id, action, protocol, rest = m.groups()
        out = []
        if state.get("acl") != acl_id:
            state["acl"] = acl_id
            out.append(f"acl number {acl_id}")

        out.append(" " + self._build_acl_rule(action, protocol, rest))
        return out

    def _build_acl_rule(self, action: str, protocol: str, rest: str) -> str:
        tokens = rest.split()
        source = "any"
        source_wildcard = None
        destination = "any"
        destination_wildcard = None
        port = None

        if tokens:
            source = tokens.pop(0)
        if source != "any" and tokens:
            source_wildcard = tokens.pop(0)
        if tokens:
            destination = tokens.pop(0)
        if destination != "any" and tokens:
            destination_wildcard = tokens.pop(0)
        if len(tokens) >= 2 and tokens[0] == "eq":
            port = tokens[1]

        parts = [f"rule {action} {protocol}"]
        parts.extend(["source", source])
        if source_wildcard:
            parts.append(source_wildcard)
        parts.extend(["destination", destination])
        if destination_wildcard:
            parts.append(destination_wildcard)
        if port:
            parts.extend(["destination-port", "eq", port])
        return " ".join(parts)

    def _to_h3c(self, stripped: str, lower: str, indent: str, from_vendor: str, state: dict):
        if lower.startswith("hostname "):
            return "sysname " + stripped.split(maxsplit=1)[1]
        if lower.startswith("sysname "):
            return stripped
        m = re.match(r"^vlan\s+(\S.*)", stripped, re.IGNORECASE)
        if m:
            vlan_val = m.group(1)
            if from_vendor in ("huawei", "h3c"):
                return stripped
            vlans = self._parse_vlan_list(vlan_val)
            if len(vlans) == 1:
                return f"vlan {vlans[0]}"
            return f"vlan {' to '.join(str(v) for v in vlans)}"
        # SVI: Cisco/Ruijie Vlan N -> H3C Vlan-interface N
        m = re.match(r"^interface\s+Vlan(\d+)$", stripped, re.IGNORECASE)
        if m:
            return f"interface Vlan-interface{m.group(1)}"
        if lower.startswith("interface "):
            return "interface " + self._normalize_interface_to_h3c(stripped.split(maxsplit=1)[1])
        if lower == "switchport mode trunk":
            return indent + "port link-type trunk"
        if lower == "switchport mode access":
            return indent + "port link-type access"
        m = re.match(r"switchport\s+trunk\s+allowed\s+vlan\s+(.+)", stripped, re.IGNORECASE)
        if m:
            return indent + "port trunk permit vlan " + self._normalize_vlan_list(m.group(1))
        m = re.match(r"switchport\s+access\s+vlan\s+(.+)", stripped, re.IGNORECASE)
        if m:
            return indent + "port default vlan " + self._normalize_vlan_list(m.group(1))
        m = re.match(r"(channel-group|eth-trunk|port-group)\s+(\d+)(?:\s+mode\s+\S+)?", stripped, re.IGNORECASE)
        if m:
            return indent + f"port link-aggregation group {m.group(2)}"
        if lower.startswith("port trunk allow-pass vlan "):
            return indent + stripped.replace("allow-pass", "permit", 1)
        if lower in ("spanning-tree portfast", "stp edged-port"):
            return indent + "stp edged-port"
        if lower.startswith("stp edged-port enable"):
            return indent + "stp edged-port"
        if lower.startswith(("port link-type ", "port default vlan ", "ip address ", "description ")):
            return indent + stripped
        if lower == "no shutdown":
            return indent + stripped
        if lower == "shutdown":
            return indent + stripped
        if lower == "undo shutdown":
            return indent + stripped
        # SVI: Huawei Vlanif -> H3C Vlan-interface
        m = re.match(r"^interface\s+Vlanif(\d+)$", stripped, re.IGNORECASE)
        if m:
            return f"interface Vlan-interface{m.group(1)}"
        # OSPF
        m = re.match(r"router\s+ospf\s+(\S+)", lower)
        if m:
            state["in_bgp"] = False
            return stripped
        m = re.match(r"ospf\s+(\S+)", lower)
        if m:
            state["in_bgp"] = False
            return stripped
        if lower.startswith("router-id "):
            return indent + stripped
        if lower.startswith("area "):
            return indent + stripped
        if lower.startswith("network ") and not state.get("in_bgp"):
            return indent + stripped
        if lower.startswith("silent-interface"):
            return indent + stripped
        if lower.startswith("undo silent-interface"):
            return indent + stripped
        # BGP
        m = re.match(r"router\s+bgp\s+(\S+)", lower)
        if m:
            state["in_bgp"] = True
            return stripped
        m = re.match(r"bgp\s+(\S+)", lower)
        if m:
            state["in_bgp"] = True
            return stripped
        m = re.match(r"neighbor\s+(\S+)\s+remote-as\s+(\S+)", lower)
        if m:
            return f" peer {m.group(1)} as-number {m.group(2)}"
        m = re.match(r"peer\s+(\S+)\s+as-number\s+(\S+)", lower)
        if m:
            return stripped
        m = re.match(r"network\s+(\S+)\s+mask\s+(\S+)", lower)
        if m:
            return indent + stripped
        if lower.startswith("ipv4-family unicast"):
            return None
        # Static route
        m = re.match(r"ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$", stripped, re.IGNORECASE)
        if m:
            route = f"ip route-static {m.group(1)} {m.group(2)} {m.group(3)}"
            if m.group(4):
                return [route, f"# MANUAL_REVIEW route options: {m.group(4)}"]
            return route
        if lower.startswith("ip route-static "):
            m = re.match(r"ip route-static\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$", stripped, re.IGNORECASE)
            if m:
                route = f"ip route-static {m.group(1)} {m.group(2)} {m.group(3)}"
                if m.group(4):
                    return [route, f"# MANUAL_REVIEW route options: {m.group(4)}"]
                return route
        # VRF
        m = re.match(r"vrf\s+definition\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return f"ip vpn-instance {m.group(1)}"
        m = re.match(r"ip\s+vpn-instance\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return stripped
        if lower.startswith("rd "):
            return indent + "route-distinguisher " + stripped.split(maxsplit=1)[1]
        if lower.startswith("route-target "):
            return indent + "vpn-target " + stripped.split(maxsplit=1)[1]
        if lower.startswith("route-distinguisher "):
            return indent + stripped
        if lower.startswith("vpn-target "):
            return indent + stripped
        # BGP neighbor sub-commands -> MANUAL_REVIEW
        if lower.startswith("neighbor ") or lower.startswith(" peer "):
            return indent + self._manual_review_comment(stripped, "h3c", indent)
        # Route-map / prefix-list -> MANUAL_REVIEW
        if lower.startswith(("route-map ", "route-policy ", "ip prefix-list ", "prefix-list ")):
            return indent + self._manual_review_comment(stripped, "h3c", indent)
        # Unknown spanning-tree / STP features -> MANUAL_REVIEW
        if lower.startswith(("spanning-tree ", "stp ", "bpduguard", "loopguard", "rootguard")):
            if lower in ("stp edged-port",) or lower.startswith(("stp edged-port", "spanning-tree portfast")):
                return indent + stripped
            return indent + self._manual_review_comment(stripped, "h3c", indent)
        return indent + stripped

    def _to_ruijie(self, stripped: str, lower: str, indent: str, from_vendor: str, state: dict):
        if lower.startswith("sysname "):
            return "hostname " + stripped.split(maxsplit=1)[1]
        if lower.startswith("hostname "):
            return stripped
        # VLAN batch handling
        m = re.match(r"^vlan\s+batch\s+(.+)", stripped, re.IGNORECASE)
        if m:
            vlans = self._parse_vlan_list(m.group(1))
            return "vlan " + self._format_vlans_cisco(vlans)
        m = re.match(r"^vlan\s+(\S.*)", stripped, re.IGNORECASE)
        if m:
            vlan_val = m.group(1)
            vlans = self._parse_vlan_list(vlan_val)
            cisco_vlans = self._format_vlans_cisco(vlans)
            return f"vlan {cisco_vlans}"
        # SVI
        m = re.match(r"^interface\s+Vlanif(\d+)$", stripped, re.IGNORECASE)
        if m:
            return f"interface Vlan{m.group(1)}"
        m = re.match(r"^interface\s+Vlan-interface(\d+)$", stripped, re.IGNORECASE)
        if m:
            return f"interface Vlan{m.group(1)}"
        if lower.startswith("interface "):
            name = self._normalize_interface_to_ruijie(stripped.split(maxsplit=1)[1])
            if name is None:
                state["unsupported_interface"] = True
                return self._manual_review_comment(stripped, "ruijie", indent)
            state["unsupported_interface"] = False
            return "interface " + name
        if state.get("unsupported_interface") and indent:
            return self._manual_review_comment(stripped, "ruijie", indent)
        if lower.startswith("description "):
            return indent + stripped
        if lower.startswith("ip address ") and lower.endswith(" sub"):
            return indent + stripped[:-4] + " secondary"
        if lower.startswith("ip address "):
            return indent + stripped
        if lower == "no shutdown":
            return indent + stripped
        if lower == "shutdown":
            return indent + stripped
        if lower == "undo shutdown":
            return indent + "no shutdown"
        if lower.startswith("port link-type trunk"):
            return indent + "switchport mode trunk"
        if lower.startswith("port link-type access"):
            return indent + "switchport mode access"
        m = re.match(r"port trunk (allow-pass|permit) vlan\s+(.+)", stripped, re.IGNORECASE)
        if m:
            return indent + "switchport trunk allowed vlan " + self._normalize_vlan_list_cisco(m.group(2))
        m = re.match(r"port default vlan\s+(.+)", stripped, re.IGNORECASE)
        if m:
            return indent + "switchport access vlan " + self._normalize_vlan_list_cisco(m.group(1))
        m = re.match(r"(eth-trunk|port link-aggregation group|bridge-aggregation)\s+(\d+)", stripped, re.IGNORECASE)
        if m:
            return indent + f"port-group {m.group(2)} mode active"
        m = re.match(r"channel-group\s+(\d+)(?:\s+mode\s+\S+)?", stripped, re.IGNORECASE)
        if m:
            return indent + f"port-group {m.group(1)} mode active"
        if lower in ("spanning-tree portfast", "stp edged-port"):
            return indent + "spanning-tree portfast"
        if lower.startswith("stp edged-port enable"):
            return indent + "spanning-tree portfast"
        # OSPF coverage
        m = re.match(r"router\s+ospf\s+(\S+)", lower)
        if m:
            state["in_bgp"] = False
            return stripped
        m = re.match(r"ospf\s+(\S+)", lower)
        if m:
            state["in_bgp"] = False
            return f"router ospf {m.group(1)}"
        if lower.startswith("router-id "):
            return indent + stripped
        if lower.startswith("area "):
            return indent + stripped
        if lower.startswith("network ") and not state.get("in_bgp"):
            return indent + stripped
        if lower.startswith("silent-interface"):
            return indent + "passive-interface " + lower.split(maxsplit=1)[1]
        if lower.startswith("undo silent-interface"):
            return indent + "no passive-interface " + lower.split(maxsplit=2)[2]
        # BGP coverage
        m = re.match(r"router\s+bgp\s+(\S+)", lower)
        if m:
            state["in_bgp"] = True
            return stripped
        m = re.match(r"bgp\s+(\S+)", lower)
        if m:
            state["in_bgp"] = True
            return stripped
        m = re.match(r"neighbor\s+(\S+)\s+remote-as\s+(\S+)", lower)
        if m:
            return f" neighbor {m.group(1)} remote-as {m.group(2)}"
        m = re.match(r"peer\s+(\S+)\s+as-number\s+(\S+)", lower)
        if m:
            return stripped
        if lower.startswith("ipv4-family unicast"):
            return None
        m = re.match(r"ip route-static\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$", stripped, re.IGNORECASE)
        if m:
            route = f"ip route {m.group(1)} {m.group(2)} {m.group(3)}"
            if m.group(4):
                return [route, f"! MANUAL_REVIEW route options: {m.group(4)}"]
            return route
        if lower.startswith("ip route "):
            return stripped
        if lower.startswith("switchport "):
            return indent + stripped
        # Route-map / prefix-list -> MANUAL_REVIEW
        if lower.startswith(("route-map ", "route-policy ", "ip prefix-list ", "prefix-list ")):
            return indent + self._manual_review_comment(stripped, "ruijie", indent)
        from_vendor_lower = (from_vendor or "").lower()
        if from_vendor_lower in ("cisco", "huawei", "h3c"):
            return self._manual_review_comment(stripped, "ruijie", indent)
        return stripped

    def _normalize_vlan_list(self, value: str) -> str:
        return value.replace(",", " ")

    def _normalize_vlan_list_cisco(self, value: str) -> str:
        normalized = re.sub(r"(?i)\b(\d+)\s+to\s+(\d+)\b", r"\1-\2", value)
        return ",".join(part for part in re.split(r"[\s,]+", normalized.strip()) if part)

    def _normalize_interface_to_huawei(self, name: str) -> str:
        normalized = re.sub(r"(?i)^Vlan-interface(\d+)$", r"Vlanif\1", name)
        normalized = re.sub(r"(?i)^Port-channel(\d+)$", r"Eth-Trunk\1", normalized)
        normalized = re.sub(r"(?i)^AggregatePort\s*(\d+)$", r"Eth-Trunk\1", normalized)
        normalized = re.sub(r"(?i)^TenGigabitEthernet", "XGigabitEthernet", normalized)
        normalized = re.sub(r"(?i)^Bridge-Aggregation(\d+)$", r"Eth-Trunk\1", normalized)
        return normalized

    def _normalize_interface_to_h3c(self, name: str) -> str:
        normalized = re.sub(r"(?i)^Port-channel(\d+)$", r"Bridge-Aggregation\1", name)
        normalized = re.sub(r"(?i)^AggregatePort\s*(\d+)$", r"Bridge-Aggregation\1", normalized)
        normalized = re.sub(r"(?i)^Vlanif(\d+)$", r"Vlan-interface\1", normalized)
        normalized = re.sub(r"(?i)^Vlan(\d+)$", r"Vlan-interface\1", normalized)
        normalized = re.sub(r"(?i)^TenGigabitEthernet", "XGigabitEthernet", normalized)
        return normalized

    def _normalize_interface_to_cisco(self, name: str) -> str:
        normalized = re.sub(r"(?i)^Vlan-interface(\d+)$", r"Vlan\1", name)
        normalized = re.sub(r"(?i)^Vlanif(\d+)$", r"Vlan\1", normalized)
        normalized = re.sub(r"(?i)^Bridge-Aggregation(\d+)$", r"Port-channel\1", normalized)
        normalized = re.sub(r"(?i)^Eth-Trunk(\d+)$", r"Port-channel\1", normalized)
        normalized = re.sub(r"(?i)^AggregatePort\s*(\d+)$", r"Port-channel\1", normalized)
        normalized = re.sub(r"(?i)^XGigabitEthernet", "TenGigabitEthernet", normalized)
        normalized = re.sub(r"(?i)^LoopBack(\d+)$", r"Loopback\1", normalized)
        normalized = re.sub(r"(?i)^NULL(\d+)$", r"Null\1", normalized)
        if re.match(r"(?i)^MEth", normalized):
            return None
        return normalized

    def _normalize_interface_to_ruijie(self, name: str) -> Optional[str]:
        normalized = re.sub(r"(?i)^Vlan-interface(\d+)$", r"Vlan\1", name)
        normalized = re.sub(r"(?i)^Vlanif(\d+)$", r"Vlan\1", normalized)
        normalized = re.sub(r"(?i)^Bridge-Aggregation(\d+)$", r"AggregatePort \1", normalized)
        normalized = re.sub(r"(?i)^Eth-Trunk(\d+)$", r"AggregatePort \1", normalized)
        normalized = re.sub(r"(?i)^Port-channel(\d+)$", r"AggregatePort \1", normalized)
        normalized = re.sub(r"(?i)^XGigabitEthernet", "TenGigabitEthernet", normalized)
        normalized = re.sub(r"(?i)^LoopBack(\d+)$", r"Loopback\1", normalized)
        normalized = re.sub(r"(?i)^NULL(\d+)$", r"Null\1", normalized)
        if re.match(r"(?i)^MEth", normalized):
            return None
        return normalized

    def _parse_vlan_list(self, value: str) -> list:
        parts = re.split(r"[\s,]+", value.strip())
        result = []
        for p in parts:
            if p.lower() == "to" or not p:
                continue
            if "-" in p:
                try:
                    lo, hi = p.split("-", 1)
                    result.extend(range(int(lo), int(hi) + 1))
                except ValueError:
                    result.append(p)
            else:
                try:
                    result.append(int(p))
                except ValueError:
                    result.append(p)
        return result

    def _format_vlans_cisco(self, vlans: list) -> str:
        if not vlans:
            return ""
        groups = [[vlans[0], vlans[0]]]
        for v in vlans[1:]:
            if isinstance(v, int) and isinstance(groups[-1][1], int) and v == groups[-1][1] + 1:
                groups[-1][1] = v
            else:
                groups.append([v, v])
        return ",".join(
            str(lo) if lo == hi else f"{lo}-{hi}"
            for lo, hi in groups
        )

    def _format_vlans_huawei_batch(self, vlans: list) -> str:
        if not vlans:
            return ""
        groups = [[vlans[0], vlans[0]]]
        for v in vlans[1:]:
            if isinstance(v, int) and isinstance(groups[-1][1], int) and v == groups[-1][1] + 1:
                groups[-1][1] = v
            else:
                groups.append([v, v])
        parts = []
        for lo, hi in groups:
            if lo == hi:
                parts.append(str(lo))
            else:
                parts.append(f"{lo} to {hi}")
        return " ".join(parts)

    def _translate_vrp_acl_rule_to_cisco(self, stripped: str) -> str:
        tokens = stripped.split()
        if not tokens or tokens[0].lower() != "rule":
            return self._manual_review_comment(stripped, "cisco")
        tokens = tokens[1:]

        sequence = None
        if tokens and tokens[0].isdigit():
            sequence = tokens.pop(0)
        if not tokens:
            return self._manual_review_comment(stripped, "cisco")

        action = tokens.pop(0).lower()
        protocol = "ip"
        if tokens and tokens[0].lower() not in ("source", "destination", "time-range", "vpn-instance"):
            protocol = tokens.pop(0).lower()

        source, source_wc = "any", None
        destination, destination_wc = "any", None
        destination_port = None

        idx = 0
        while idx < len(tokens):
            key = tokens[idx].lower()
            if key == "source" and idx + 1 < len(tokens):
                source = tokens[idx + 1]
                idx += 2
                if source.lower() != "any" and idx < len(tokens) and not self._is_acl_keyword(tokens[idx]):
                    source_wc = tokens[idx]
                    idx += 1
                continue
            if key == "destination" and idx + 1 < len(tokens):
                destination = tokens[idx + 1]
                idx += 2
                if destination.lower() != "any" and idx < len(tokens) and not self._is_acl_keyword(tokens[idx]):
                    destination_wc = tokens[idx]
                    idx += 1
                continue
            if key in ("destination-port", "source-port") and idx + 2 < len(tokens):
                if tokens[idx + 1].lower() == "eq":
                    destination_port = tokens[idx + 2]
                idx += 3
                continue
            idx += 1

        parts = []
        if sequence is not None:
            parts.append(sequence)
        parts.extend([
            action,
            protocol,
            self._format_cisco_acl_endpoint(source, source_wc),
            self._format_cisco_acl_endpoint(destination, destination_wc),
        ])
        if destination_port:
            parts.extend(["eq", destination_port])
        return " ".join(parts)

    def _is_acl_keyword(self, token: str) -> bool:
        return token.lower() in {
            "source",
            "destination",
            "source-port",
            "destination-port",
            "time-range",
            "vpn-instance",
            "logging",
        }

    def _format_cisco_acl_endpoint(self, value: str, wildcard: Optional[str]) -> str:
        if not value or value.lower() == "any":
            return "any"
        if wildcard in (None, ""):
            return value
        if wildcard == "0":
            return "host " + value
        return value + " " + wildcard

    def _direction_to_cisco(self, direction: str) -> str:
        return "in" if direction.lower() == "inbound" else "out"

    def _direction_to_cisco_qos(self, direction: str) -> str:
        return "input" if direction.lower() == "inbound" else "output"

    def _translate_huawei_snmp_to_cisco(self, stripped: str) -> Optional[str]:
        lower = stripped.lower()
        if lower == "snmp-agent trap enable":
            return "snmp-server enable traps"
        m = re.match(r"snmp-agent\s+trap\s+source\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return "snmp-server trap-source " + self._normalize_interface_to_cisco(m.group(1))
        m = re.match(
            r"snmp-agent\s+target-host\s+trap\s+address\s+udp-domain\s+(\S+)\s+params\s+securityname\s+(\S+)\s+v3\s+privacy",
            stripped,
            re.IGNORECASE,
        )
        if m:
            return f"snmp-server host {m.group(1)} version 3 priv {m.group(2)}"
        if lower.startswith("snmp-agent community "):
            return self._manual_review_comment("snmp-agent community <redacted>", "cisco")
        if lower.startswith("snmp-agent "):
            return self._manual_review_comment(stripped, "cisco")
        return None

    def _to_firewall_manual_review(self, stripped: str, indent: str, to_vendor: str, from_vendor: str) -> str:
        if (from_vendor or "").lower() == (to_vendor or "").lower():
            return indent + stripped
        return self._manual_review_comment(stripped, to_vendor, indent)

    def _to_hillstone_firewall(self, stripped: str, lower: str, indent: str, from_vendor: str, state: dict) -> Optional[Union[str, list]]:
        # Redact secrets
        if re.search(r"(cipher|password)\s+\S+", lower):
            return "# MANUAL_REVIEW <redacted> (secret/cipher)"
        if (from_vendor or "").lower() == "hillstone":
            return stripped

        # Huawei USG security-policy multi-line block (inside block only)
        if state.get("_in_secpol"):
            if not indent:
                # Exit is handled by _check_flush_secpol_at_line_boundary in _translate_line
                # This branch should not be reached for a non-indented line
                return None
            # Inside secpol block
            m = re.match(r"rule\s+name\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                state["_secpol_seen_rule"] = True
                # Flush previous rule if any
                secpol = state.get("_secpol")
                state["_secpol"] = {"name": m.group(1)}
                if secpol and secpol.get("name"):
                    if secpol.get("action"):
                        return self._render_policy(secpol)
                    else:
                        return self._manual_review_comment(
                            f"security-policy name={secpol['name']} incomplete: missing action",
                            "hillstone",
                        )
                return None

            for key, pat in (
                ("src_zone", r"source-zone\s+(\S+)"),
                ("dst_zone", r"destination-zone\s+(\S+)"),
                ("src_addr", r"source-address\s+(\S+)"),
                ("dst_addr", r"destination-address\s+(\S+)"),
                ("service", r"service\s+(\S+)"),
            ):
                m = re.match(pat, stripped, re.IGNORECASE)
                if m:
                    secpol = state.get("_secpol")
                    if secpol is not None:
                        if key in secpol:
                            # Multiple values not supported by single-value target
                            name = secpol.get("name", "UNNAMED")
                            return f"# MANUAL_REVIEW security-policy rule={name} multi-{key.replace('_','-')}: {m.group(1)} (only first preserved)"
                        secpol[key] = m.group(1)
                    return None

            m = re.match(r"action\s+(permit|deny)", stripped, re.IGNORECASE)
            if m:
                pending = state.get("_secpol", {})
                pending["action"] = m.group(1)
                state["_secpol"] = None
                return self._render_policy(pending)

            # Unknown sub-line inside secpol — emit MANUAL_REVIEW
            secpol = state.get("_secpol")
            name = secpol.get("name", "UNNAMED") if secpol else "UNNAMED"
            return f"# MANUAL_REVIEW security-policy rule={name} unsupported sub-command: {stripped}"

        # Huawei USG zone
        m = re.match(r"security-zone\s+name\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            state["_last_zone"] = m.group(1)
            return f"zone {m.group(1)}"

        if indent and state.get("_last_zone"):
            m = re.match(r"add\s+interface\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                return f"# MANUAL_REVIEW zone {state['_last_zone']} interface binding: {m.group(1)}"
            state["_last_zone"] = None

        # Topsec zone
        m = re.match(r"zone\s+name\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            state["_last_zone"] = m.group(1)
            return f"zone {m.group(1)}"

        # Plain zone (Hillstone/DPtech passthrough)
        m = re.match(r"zone\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            state["_last_zone"] = m.group(1)
            return stripped

        # Huawei USG address object (multi-line)
        m = re.match(r"ip\s+address-set\s+(\S+)\s+type\s+object", stripped, re.IGNORECASE)
        if m:
            state["_addr_set"] = m.group(1)
            return None

        if state.get("_addr_set"):
            # address N IP mask prefixlen
            m = re.match(r"address\s+(\d+)\s+(\S+)\s+mask\s+(\d+)", stripped, re.IGNORECASE)
            if m:
                name = state.pop("_addr_set")
                ip = m.group(2)
                mask = self._prefixlen_to_netmask(m.group(3))
                return f"address {name} {ip} {mask}"
            # address N IP netmask (e.g. 255.255.255.0) or range
            m = re.match(r"address\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", stripped)
            if m:
                ip = m.group(2)
                third = m.group(3)
                prefix = self._netmask_to_prefixlen(third)
                name = state.pop("_addr_set")
                if prefix != third:
                    return f"address {name} {ip} {third}"
                else:
                    return self._manual_review_comment(
                        f"ip address-set {name} range {ip} {third}", "hillstone",
                    )
            # Unrecognized address-set sub-command: pop and MANUAL_REVIEW
            name = state.pop("_addr_set")
            return self._manual_review_comment(
                f"ip address-set {name} sub-command: {stripped}", "hillstone",
            )

        # Topsec address object
        m = re.match(r"address\s+name\s+(\S+)\s+ip\s+(\S+)\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return f"address {m.group(1)} {m.group(2)} {m.group(3)}"

        # DPtech address object
        m = re.match(r"object\s+address\s+(\S+)\s+(\S+)\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return f"address {m.group(1)} {m.group(2)} {m.group(3)}"

        # Hillstone address object (passthrough)
        m = re.match(r"address\s+(\S+)\s+(\S+)\s+(\S+)", lower)
        if m and from_vendor == "hillstone":
            return stripped

        # Huawei USG service object (multi-line)
        m = re.match(r"ip\s+service-set\s+(\S+)\s+type\s+object", stripped, re.IGNORECASE)
        if m:
            state["_svc_set"] = m.group(1)
            return None

        if state.get("_svc_set"):
            m = re.match(r"service\s+(\d+)\s+protocol\s+(\S+)\s+destination-port\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                name = state.pop("_svc_set")
                proto = m.group(2)
                port = m.group(3)
                return f"service {name} {proto} dst-port {port}"
            # Unrecognized service-set sub-command: pop and MANUAL_REVIEW
            name = state.pop("_svc_set")
            return self._manual_review_comment(
                f"ip service-set {name} sub-command: {stripped}", "hillstone",
            )

        # Hillstone service object (passthrough)
        m = re.match(r"service\s+(\S+)\s+(\S+)\s+dst-port\s+(\S+)", lower)
        if m and from_vendor == "hillstone":
            return stripped

        # Flat policy (Hillstone, Topsec)
        m = re.match(
            r"policy\s+(?:name\s+)?(\S+)\s+from\s+(\S+)\s+to\s+(\S+)\s+(?:src|source)\s+(\S+)\s+(?:dst|destination)\s+(\S+)\s+service\s+(\S+)\s+action\s+(permit|deny)",
            stripped,
            re.IGNORECASE,
        )
        if m:
            name, src_zone, dst_zone, src_addr, dst_addr, svc, action = m.groups()
            return [f"policy {name} from {src_zone} to {dst_zone} source {src_addr} destination {dst_addr} service {svc} action {action}",
                    f"# MANUAL_REVIEW service {svc}: verify Hillstone service object definition"]

        # Huawei USG security-policy header
        if lower.startswith("security-policy") and not lower.startswith("security-policy name"):
            state["_in_secpol"] = True
            state["_secpol"] = None
            state["_secpol_seen_rule"] = False
            return None

        return self._manual_review_comment(stripped, "hillstone", indent)

    def _check_flush_secpol_at_line_boundary(self, indent: str, state: dict) -> Optional[list]:
        if not state.get("_in_secpol"):
            return None
        if indent:
            return None
        pending = state.get("_secpol")
        seen_rule = state.pop("_secpol_seen_rule", False)
        state["_in_secpol"] = False
        state["_secpol"] = None
        output = []
        if pending and pending.get("name"):
            if pending.get("action"):
                output.append(self._render_policy(pending))
            else:
                output.append(self._manual_review_comment(
                    f"security-policy name={pending['name']} incomplete: missing action/destination/service",
                    "hillstone",
                ))
        elif not seen_rule:
            output.append(self._manual_review_comment(
                "security-policy (incomplete: no rule defined)",
                "hillstone",
            ))
        return output

    def _render_policy(self, rule: dict) -> str:
        name = rule.get("name", "UNNAMED")
        src_zone = rule.get("src_zone", "any")
        dst_zone = rule.get("dst_zone", "any")
        src_addr = rule.get("src_addr", "any")
        dst_addr = rule.get("dst_addr", "any")
        svc = rule.get("service", "any")
        action = rule.get("action", "permit")
        return f"policy {name} from {src_zone} to {dst_zone} source {src_addr} destination {dst_addr} service {svc} action {action}"

    def _flush_pending_state(self, state: dict, to_vendor: str) -> Optional[list]:
        result = []
        if state.get("_in_secpol"):
            pending = state.get("_secpol")
            seen_rule = state.pop("_secpol_seen_rule", False)
            state["_in_secpol"] = False
            state["_secpol"] = None
            if pending and pending.get("name"):
                if pending.get("action"):
                    result.append(self._render_policy(pending))
                else:
                    result.append(self._manual_review_comment(
                        f"security-policy name={pending['name']} incomplete: missing action/destination/service",
                        to_vendor,
                    ))
            elif not seen_rule:
                result.append(self._manual_review_comment(
                    "security-policy (incomplete: no rule defined)",
                    to_vendor,
                ))
        return result if result else None

    def _to_huawei_usg_firewall(self, stripped: str, lower: str, indent: str, from_vendor: str, state: dict) -> Optional[Union[str, list]]:
        if re.search(r"(cipher|password)\s+\S+", lower):
            return "# MANUAL_REVIEW <redacted> (secret/cipher)"
        if (from_vendor or "").lower() == "huawei_usg":
            return stripped

        # Zone (Hillstone, DPtech)
        m = re.match(r"zone\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return f"security-zone name {m.group(1)}"

        # Huawei USG zone (passthrough)
        m = re.match(r"security-zone\s+name\s+(\S+)", lower)
        if m and from_vendor == "huawei_usg":
            return stripped

        # Address object (Hillstone flat -> Huawei USG multi-line)
        m = re.match(r"address\s+(\S+)\s+(\S+)\s+(\S+)", stripped, re.IGNORECASE)
        if m and from_vendor == "hillstone":
            name, ip, mask = m.groups()
            prefix = self._netmask_to_prefixlen(mask)
            return [f"ip address-set {name} type object", f" address 0 {ip} mask {prefix}"]

        # Address object (DPtech -> Huawei USG multi-line)
        m = re.match(r"object\s+address\s+(\S+)\s+(\S+)\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            name, ip, mask = m.groups()
            prefix = self._netmask_to_prefixlen(mask)
            return [f"ip address-set {name} type object", f" address 0 {ip} mask {prefix}"]

        # Huawei USG address object multi-line (passthrough)
        m = re.match(r"ip\s+address-set\s+(\S+)\s+type\s+object", stripped, re.IGNORECASE)
        if m:
            state["_addr_set"] = m.group(1)
            return None

        if state.get("_addr_set"):
            m = re.match(r"address\s+(\d+)\s+(\S+)\s+mask\s+(\d+)", stripped, re.IGNORECASE)
            if m:
                state.pop("_addr_set")
                return stripped
            # Unrecognized sub-command in address-set: pop and MANUAL_REVIEW
            name = state.pop("_addr_set")
            return self._manual_review_comment(
                f"ip address-set {name} sub-command: {stripped}", "huawei_usg",
            )

        # Service object (Hillstone flat -> Huawei USG multi-line)
        m = re.match(r"service\s+(\S+)\s+(\S+)\s+dst-port\s+(\S+)", stripped, re.IGNORECASE)
        if m and from_vendor == "hillstone":
            name, proto, port = m.groups()
            return [f"ip service-set {name} type object", f" service 0 protocol {proto} destination-port {port}"]

        # Huawei USG service object multi-line (passthrough)
        m = re.match(r"ip\s+service-set\s+(\S+)\s+type\s+object", stripped, re.IGNORECASE)
        if m:
            state["_svc_set"] = m.group(1)
            return None

        if state.get("_svc_set"):
            m = re.match(r"service\s+(\d+)\s+protocol\s+(\S+)\s+destination-port\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                state.pop("_svc_set")
                return stripped
            # Unrecognized sub-command in service-set: pop and MANUAL_REVIEW
            name = state.pop("_svc_set")
            return self._manual_review_comment(
                f"ip service-set {name} sub-command: {stripped}", "huawei_usg",
            )

        # Policy (Hillstone flat -> Huawei USG multi-line)
        m = re.match(
            r"policy\s+(\S+)\s+from\s+(\S+)\s+to\s+(\S+)\s+source\s+(\S+)\s+destination\s+(\S+)\s+service\s+(\S+)\s+action\s+(permit|deny)",
            stripped,
            re.IGNORECASE,
        )
        if m:
            name, src_zone, dst_zone, src_addr, dst_addr, svc, action = m.groups()
            return [
                "security-policy",
                f" rule name {name}",
                f"  source-zone {src_zone}",
                f"  destination-zone {dst_zone}",
                f"  destination-address {dst_addr}",
                f"  service {svc}",
                f"  action {action}",
            ]

        # Policy (DPtech single-line -> Huawei USG multi-line)
        m = re.match(
            r"security-policy\s+name\s+(\S+)\s+source-zone\s+(\S+)\s+destination-zone\s+(\S+)\s+destination-address\s+(\S+)\s+service\s+(\S+)\s+action\s+(permit|deny)",
            stripped,
            re.IGNORECASE,
        )
        if m:
            name, src_zone, dst_zone, dst_addr, svc, action = m.groups()
            return [
                "security-policy",
                f" rule name {name}",
                f"  source-zone {src_zone}",
                f"  destination-zone {dst_zone}",
                f"  destination-address {dst_addr}",
                f"  service {svc}",
                f"  action {action}",
            ]

        return self._manual_review_comment(stripped, "huawei_usg", indent)

    def _prefixlen_to_netmask(self, prefixlen: str) -> str:
        try:
            n = int(prefixlen)
            if n < 0 or n > 32:
                return prefixlen
            mask = ((1 << n) - 1) << (32 - n) if n > 0 else 0
            return ".".join(str((mask >> (24 - i * 8)) & 0xFF) for i in range(4))
        except (ValueError, TypeError):
            return str(prefixlen)

    def _netmask_to_prefixlen(self, netmask: str) -> str:
        parts = netmask.split(".")
        if len(parts) != 4:
            return netmask
        try:
            binary = "".join(f"{int(p):08b}" for p in parts)
            cnt = binary.count("1")
            return str(cnt)
        except (ValueError, TypeError):
            return netmask

    def _manual_review_comment(self, stripped: str, to_vendor: str, indent: str = "") -> str:
        prefix = "!" if (to_vendor or "").lower() in ("cisco", "ruijie") else "#"
        return indent + f"{prefix} MANUAL_REVIEW unsupported source command: {stripped}"
