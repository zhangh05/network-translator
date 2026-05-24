# -*- coding: utf-8 -*-
"""Deterministic rule-based fallback translator for common network commands."""

import re
from typing import List, Optional


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

        if not output:
            return ""
        return self._wrap("\n".join(output), to_vendor)

    def _wrap(self, body: str, vendor: str) -> str:
        return f"```{vendor}\n{body.strip()}\n```"

    def _translate_line(self, line: str, from_vendor: str, to_vendor: str, state: dict):
        stripped = line.strip()
        indent = line[: len(line) - len(line.lstrip())]
        lower = stripped.lower()

        if to_vendor == "huawei":
            return self._to_huawei(stripped, lower, indent, from_vendor, state)
        if to_vendor == "h3c":
            return self._to_h3c(stripped, lower, indent)
        if to_vendor == "cisco":
            return self._to_cisco(stripped, lower, indent, from_vendor, state)
        if to_vendor == "ruijie":
            return self._to_ruijie(stripped, lower, indent, from_vendor, state)
        if to_vendor in ("hillstone", "topsec", "dptech", "huawei_usg"):
            return self._to_firewall_manual_review(stripped, indent, to_vendor, from_vendor)
        return line

    def _to_huawei(self, stripped: str, lower: str, indent: str, from_vendor: str, state: dict):
        if lower.startswith("hostname "):
            return "sysname " + stripped.split(maxsplit=1)[1]
        if lower.startswith("sysname "):
            return stripped
        if re.match(r"^vlan\s+\d+", lower):
            return stripped
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

        translated_acl = self._translate_acl_to_huawei(stripped, lower, state)
        if translated_acl is not None:
            return translated_acl

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
        m = re.match(r"channel-group\s+(\d+)(?:\s+mode\s+\S+)?", stripped, re.IGNORECASE)
        if m:
            return indent + f"eth-trunk {m.group(1)}"
        return None

    def _translate_routing_to_huawei(self, stripped: str, lower: str, indent: str, state: dict):
        m = re.match(r"router\s+ospf\s+(\S+)", lower)
        if m:
            state["in_bgp"] = False
            return "ospf " + m.group(1)
        if lower.startswith("router-id "):
            return indent + stripped
        if lower.startswith("network ") and not state.get("in_bgp"):
            return indent + stripped

        m = re.match(r"router\s+bgp\s+(\S+)", lower)
        if m:
            state["in_bgp"] = True
            return ["bgp " + m.group(1), " ipv4-family unicast"]
        m = re.match(r"neighbor\s+(\S+)\s+remote-as\s+(\S+)", lower)
        if m:
            return f" peer {m.group(1)} as-number {m.group(2)}"
        m = re.match(r"network\s+(\S+)\s+mask\s+(\S+)", lower)
        if m:
            return f" network {m.group(1)} {m.group(2)}"

        m = re.match(r"ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)", lower)
        if m:
            return f"ip route-static {m.group(1)} {m.group(2)} {m.group(3)}"
        if lower.startswith("ip route-static "):
            return stripped
        return None

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
        source_wildcard: Optional[str] = None
        destination = "any"
        destination_wildcard: Optional[str] = None
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

    def _to_h3c(self, stripped: str, lower: str, indent: str):
        if lower.startswith("hostname "):
            return "sysname " + stripped.split(maxsplit=1)[1]
        if lower.startswith("sysname "):
            return stripped
        if re.match(r"^vlan\s+\d+", lower):
            return stripped
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
        m = re.match(r"port-group\s+(\d+)(?:\s+mode\s+\S+)?", stripped, re.IGNORECASE)
        if m:
            return indent + f"port link-aggregation group {m.group(1)}"
        if lower.startswith("port trunk allow-pass vlan "):
            return indent + stripped.replace("allow-pass", "permit", 1)
        if lower.startswith("stp edged-port enable"):
            return indent + "stp edged-port"
        if lower.startswith(("port link-type ", "port default vlan ", "ip address ", "description ")):
            return indent + stripped
        return indent + stripped

    def _to_ruijie(self, stripped: str, lower: str, indent: str, from_vendor: str, state: dict):
        if lower.startswith("sysname "):
            return "hostname " + stripped.split(maxsplit=1)[1]
        if lower.startswith("hostname "):
            return stripped
        if lower.startswith("vlan batch "):
            return "vlan " + self._normalize_vlan_list_cisco(stripped.split(maxsplit=2)[2])
        if re.match(r"^vlan\s+\d+", lower):
            return "vlan " + self._normalize_vlan_list_cisco(stripped.split(maxsplit=1)[1])
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
        m = re.match(r"(eth-trunk|port link-aggregation group)\s+(\d+)", stripped, re.IGNORECASE)
        if m:
            return indent + f"port-group {m.group(2)} mode active"
        m = re.match(r"channel-group\s+(\d+)(?:\s+mode\s+\S+)?", stripped, re.IGNORECASE)
        if m:
            return indent + f"port-group {m.group(1)} mode active"
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
        if from_vendor in ("cisco", "huawei", "h3c"):
            return self._manual_review_comment(stripped, "ruijie", indent)
        return stripped

    def _to_cisco(self, stripped: str, lower: str, indent: str, from_vendor: str, state: dict):
        if lower.startswith("sysname "):
            return "hostname " + stripped.split(maxsplit=1)[1]
        if lower.startswith("hostname "):
            return stripped
        if lower.startswith("vlan batch "):
            state["unsupported_interface"] = False
            return "vlan " + self._normalize_vlan_list_cisco(stripped.split(maxsplit=2)[2])
        if re.match(r"^vlan\s+\d+", lower):
            state["unsupported_interface"] = False
            return "vlan " + self._normalize_vlan_list_cisco(stripped.split(maxsplit=1)[1])
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
        if lower.startswith("bgp "):
            m = re.match(r"bgp\s+(\S+)", lower)
            if m:
                state["in_bgp"] = True
                return f"router bgp {m.group(1)}"
        m = re.match(r"peer\s+(\S+)\s+as-number\s+(\S+)", lower)
        if m:
            return f" neighbor {m.group(1)} remote-as {m.group(2)}"
        if lower.startswith("ipv4-family unicast"):
            return None
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
        m = re.match(r"(eth-trunk|port link-aggregation group)\s+(\d+)", lower)
        if m:
            return indent + f"channel-group {m.group(2)} mode active"
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

        if from_vendor in ("huawei", "h3c"):
            return self._manual_review_comment(stripped, "cisco", indent)
        return stripped

    def _normalize_vlan_list(self, value: str) -> str:
        return value.replace(",", " ")

    def _normalize_vlan_list_cisco(self, value: str) -> str:
        normalized = re.sub(r"(?i)\b(\d+)\s+to\s+(\d+)\b", r"\1-\2", value)
        return ",".join(part for part in re.split(r"[\s,]+", normalized.strip()) if part)

    def _normalize_interface_to_huawei(self, name: str) -> str:
        normalized = re.sub(r"(?i)^Port-channel(\d+)$", r"Eth-Trunk\1", name)
        normalized = re.sub(r"(?i)^AggregatePort\s*(\d+)$", r"Eth-Trunk\1", normalized)
        normalized = re.sub(r"(?i)^GigabitEthernet", "XGigabitEthernet", normalized)
        return normalized

    def _normalize_interface_to_h3c(self, name: str) -> str:
        normalized = re.sub(r"(?i)^Port-channel(\d+)$", r"Bridge-Aggregation\1", name)
        normalized = re.sub(r"(?i)^AggregatePort\s*(\d+)$", r"Bridge-Aggregation\1", normalized)
        normalized = re.sub(r"(?i)^Vlanif(\d+)$", r"Vlan-interface\1", normalized)
        normalized = re.sub(r"(?i)^Vlan(\d+)$", r"Vlan-interface\1", normalized)
        return normalized

    def _normalize_interface_to_cisco(self, name: str) -> str:
        normalized = re.sub(r"(?i)^Vlan-interface(\d+)$", r"Vlan\1", name)
        normalized = re.sub(r"(?i)^Vlanif(\d+)$", r"Vlan\1", normalized)
        normalized = re.sub(r"(?i)^Bridge-Aggregation(\d+)$", r"Port-channel\1", normalized)
        normalized = re.sub(r"(?i)^Eth-Trunk(\d+)$", r"Port-channel\1", normalized)
        normalized = re.sub(r"(?i)^XGigabitEthernet", "GigabitEthernet", normalized)
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

    def _manual_review_comment(self, stripped: str, to_vendor: str, indent: str = "") -> str:
        prefix = "!" if (to_vendor or "").lower() in ("cisco", "ruijie") else "#"
        return indent + f"{prefix} MANUAL_REVIEW unsupported source command: {stripped}"
