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
            if name.startswith("GigabitEthernet"):
                name = "XGigabitEthernet" + name[len("GigabitEthernet") :]
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
            return stripped
        if lower.startswith("port trunk allow-pass vlan "):
            return indent + stripped.replace("allow-pass", "permit", 1)
        if lower.startswith("stp edged-port enable"):
            return indent + "stp edged-port"
        if lower.startswith(("port link-type ", "port default vlan ", "ip address ", "description ")):
            return indent + stripped
        return indent + stripped

    def _to_cisco(self, stripped: str, lower: str, indent: str, from_vendor: str, state: dict):
        if lower.startswith("sysname "):
            return "hostname " + stripped.split(maxsplit=1)[1]
        if lower.startswith("hostname "):
            return stripped
        if lower.startswith("interface "):
            name = stripped.split(maxsplit=1)[1]
            if name.lower().startswith("xgigabitethernet"):
                name = "GigabitEthernet" + name[len("XGigabitEthernet") :]
            return f"interface {name}"
        if lower.startswith("description "):
            return indent + stripped
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
        m = re.match(r"ip route-static\s+(\S+)\s+(\S+)\s+(\S+)", lower)
        if m:
            return f"ip route {m.group(1)} {m.group(2)} {m.group(3)}"

        if lower.startswith("port link-type trunk"):
            return indent + "switchport mode trunk"
        if lower.startswith("port link-type access"):
            return indent + "switchport mode access"
        m = re.match(r"port default vlan\s+(.+)", lower)
        if m:
            return indent + "switchport access vlan " + self._normalize_vlan_list(m.group(1))
        m = re.match(r"port trunk (allow-pass|permit) vlan\s+(.+)", lower)
        if m:
            return indent + "switchport trunk allowed vlan " + self._normalize_vlan_list(m.group(2))
        if lower.startswith("stp edged-port"):
            return indent + "spanning-tree portfast"

        if lower.startswith("acl number "):
            state["acl"] = lower.split()[-1]
            return None
        m = re.match(r"rule\s+(permit|deny)\s+(\S+)\s+source\s+(.+)$", lower)
        if m and state.get("acl"):
            action, protocol, rest = m.groups()
            tokens = rest.split()
            src = tokens[0] if tokens else "any"
            idx = 1
            src_wc = None
            if src != "any" and len(tokens) > idx:
                src_wc = tokens[idx]
                idx += 1
            if len(tokens) > idx and tokens[idx] == "destination":
                idx += 1
            dst = tokens[idx] if len(tokens) > idx else "any"
            idx += 1
            dst_wc = None
            if dst != "any" and len(tokens) > idx:
                dst_wc = tokens[idx]
                idx += 1
            port = None
            if "destination-port" in tokens:
                p = tokens.index("destination-port")
                if len(tokens) > p + 2 and tokens[p + 1] == "eq":
                    port = tokens[p + 2]
            parts = [f"access-list {state['acl']} {action} {protocol}", src]
            if src_wc:
                parts.append(src_wc)
            parts.append(dst)
            if dst_wc:
                parts.append(dst_wc)
            if port:
                parts.extend(["eq", port])
            return " ".join(parts)

        return indent + stripped if from_vendor in ("huawei", "h3c") else stripped

    def _normalize_vlan_list(self, value: str) -> str:
        return value.replace(",", " ")
