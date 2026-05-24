# -*- coding: utf-8 -*-
"""Deterministic rule-based fallback translator for common network commands.

Delegates to core/fallback/ rule modules for SWITCH / ROUTER / FIREWALL domains.
"""

import re
from typing import Dict, List, Optional, Union

from core.fallback import (
    format_vlans_cisco,
    format_vlans_huawei_batch,
    manual_review_comment,
    normalize_interface_to_cisco,
    normalize_interface_to_h3c,
    normalize_interface_to_huawei,
    normalize_interface_to_ruijie,
    normalize_vlan_list,
    normalize_vlan_list_cisco,
    parse_vlan_list,
)
from core.fallback import switch_rules as sw
from core.fallback import router_rules as rt
from core.fallback import firewall_rules as fw
from core.fallback import management_rules as mgmt
from core.fallback import acl_rules as acl


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
        state: Dict = {"acl": None, "in_bgp": False}

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

        pending = self._flush_pending_state(state, to_vendor)
        if pending:
            output.extend(pending)

        if not output:
            return ""
        return self._wrap("\n".join(output), to_vendor)

    def _wrap(self, body: str, vendor: str) -> str:
        return f"```{vendor}\n{body.strip()}\n```"

    def _translate_line(self, line: str, from_vendor: str, to_vendor: str, state: Dict):
        stripped = line.strip()
        indent = line[: len(line) - len(line.lstrip())]
        lower = stripped.lower()

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
            rv = fw.translate_to_hillstone_firewall(stripped, lower, indent, from_vendor, state)
        elif to_vendor == "huawei_usg":
            rv = fw.translate_to_huawei_usg_firewall(stripped, lower, indent, from_vendor, state)
        elif to_vendor in ("topsec", "dptech"):
            rv = fw.translate_firewall_manual_review(stripped, indent, to_vendor, from_vendor)
        else:
            rv = line

        if flush_output:
            if rv is None:
                return flush_output
            if isinstance(rv, list):
                return flush_output + rv
            return flush_output + [rv]
        return rv

    def _to_huawei(self, stripped: str, lower: str, indent: str, from_vendor: str, state: Dict):
        rv = mgmt.translate_hostname_to_huawei(stripped, lower, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_ntp_to_huawei(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_logging_to_huawei(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_aaa_to_huawei(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_snmp_to_huawei(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = sw.translate_to_huawei_switch(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = sw.translate_switching_to_huawei(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = rt.translate_routing_to_huawei(stripped, lower, indent, state)
        if rv is not None:
            return rv

        rv = rt.translate_vrf_to_huawei(stripped, lower, indent)
        if rv is not None:
            return rv

        rv = self._translate_acl_to_huawei(stripped, lower, state)
        if rv is not None:
            return rv

        rv = acl.translate_cisco_access_group_to_huawei(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_ruijie_access_group_to_huawei(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_h3c_packet_filter_to_huawei(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_cisco_named_acl_header_to_huawei(stripped)
        if rv is not None:
            return rv

        rv = acl.translate_cisco_numbered_acl(stripped)
        if rv is not None:
            if "object-group" in lower:
                return indent + manual_review_comment(stripped, "huawei", indent)
            return rv

        if lower.startswith("service-policy "):
            return indent + manual_review_comment(stripped, "huawei", indent)

        if lower.startswith(("route-map ", "route-policy ", "ip prefix-list ", "prefix-list ")):
            return indent + manual_review_comment(stripped, "huawei", indent)
        if lower.startswith(("spanning-tree ", "stp ", "bpduguard", "loopguard", "rootguard")):
            return indent + manual_review_comment(stripped, "huawei", indent)

        return stripped if from_vendor in ("h3c", "huawei") else indent + stripped

    def _to_cisco(self, stripped: str, lower: str, indent: str, from_vendor: str, state: Dict):
        rv = mgmt.translate_hostname_to_cisco(stripped, lower, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_ntp_to_cisco(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_logging_to_cisco(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_aaa_to_cisco(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_snmp_to_cisco(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_huawei_traffic_filter_to_cisco(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_h3c_packet_filter_to_cisco(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_huawei_traffic_policy_to_cisco(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_ruijie_access_group_to_cisco(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_cisco_named_acl_header_to_cisco(stripped)
        if rv is not None:
            return rv

        rv = acl.translate_huawei_acl_rule_to_cisco(stripped, lower, indent)
        if rv is not None:
            return rv

        rv = acl.translate_cisco_numbered_acl(stripped)
        if rv is not None:
            if "object-group" in lower:
                return indent + manual_review_comment(stripped, "cisco", indent)
            return rv

        rv = sw.translate_to_cisco_switch(stripped, lower, indent, from_vendor, state)
        if rv is not None:
            return rv

        rv = rt.translate_routing_to_cisco(stripped, lower, indent, state)
        if rv is not None:
            return rv

        rv = rt.translate_vrf_to_cisco(stripped, lower, indent)
        if rv is not None:
            return rv

        if lower.startswith(("port link-type ", "port default vlan ")):
            return indent + stripped
        if lower.startswith("stp edged-port"):
            return indent + "spanning-tree portfast"

        rv = self._translate_acl_and_huawei_cisco_misc(stripped, lower, indent, from_vendor, state)
        if rv is not None:
            return rv

        if lower.startswith(("route-map ", "route-policy ", "ip prefix-list ", "prefix-list ")):
            return indent + manual_review_comment(stripped, "cisco", indent)
        if lower.startswith(("spanning-tree ", "stp ", "bpduguard", "loopguard", "rootguard")):
            if not (lower.startswith("stp edged-port") or lower == "spanning-tree portfast"):
                return manual_review_comment(stripped, "cisco", indent)

        if from_vendor in ("huawei", "h3c"):
            return manual_review_comment(stripped, "cisco", indent)
        return stripped

    def _translate_acl_and_huawei_cisco_misc(self, stripped: str, lower: str, indent: str, from_vendor: str, state: Dict):
        if "object-group" in lower:
            return indent + manual_review_comment(stripped, "huawei", indent)
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

        m = re.match(r"traffic-filter\s+(inbound|outbound)\s+acl(?:\s+name)?\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return indent + f"ip access-group {m.group(2)} {self._direction_to_cisco(m.group(1))}"
        m = re.match(r"traffic-policy\s+(\S+)\s+(inbound|outbound)", stripped, re.IGNORECASE)
        if m:
            return indent + f"service-policy {self._direction_to_cisco_qos(m.group(2))} {m.group(1)}"
        m = re.match(r"packet-filter\s+(\S+)\s+(inbound|outbound)", stripped, re.IGNORECASE)
        if m:
            return indent + f"ip access-group {m.group(1)} {self._direction_to_cisco(m.group(2))}"

        return None

    def _translate_vrp_acl_rule_to_cisco(self, stripped: str) -> str:
        tokens = stripped.split()
        if not tokens or tokens[0].lower() != "rule":
            return manual_review_comment(stripped, "cisco")
        tokens = tokens[1:]
        sequence = None
        if tokens and tokens[0].isdigit():
            sequence = tokens.pop(0)
        if not tokens:
            return manual_review_comment(stripped, "cisco")
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
        parts.extend([action, protocol, self._format_cisco_acl_endpoint(source, source_wc),
                      self._format_cisco_acl_endpoint(destination, destination_wc)])
        if destination_port:
            parts.extend(["eq", destination_port])
        return " ".join(parts)

    def _is_acl_keyword(self, token: str) -> bool:
        return token.lower() in {"source", "destination", "source-port", "destination-port", "time-range", "vpn-instance", "logging"}

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
            return "snmp-server trap-source " + normalize_interface_to_cisco(m.group(1))
        m = re.match(r"snmp-agent\s+target-host\s+trap\s+address\s+udp-domain\s+(\S+)\s+params\s+securityname\s+(\S+)\s+v3\s+privacy", stripped, re.IGNORECASE)
        if m:
            return f"snmp-server host {m.group(1)} version 3 priv {m.group(2)}"
        if lower.startswith("snmp-agent community "):
            return manual_review_comment("snmp-agent community <redacted>", "cisco")
        if lower.startswith("snmp-agent "):
            return manual_review_comment(stripped, "cisco")
        return None

    def _to_h3c(self, stripped: str, lower: str, indent: str, from_vendor: str, state: Dict):
        rv = mgmt.translate_hostname_to_h3c(stripped, lower, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_ntp_to_h3c(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_logging_to_h3c(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_aaa_to_h3c(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_snmp_to_h3c(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_huawei_traffic_filter_to_h3c(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_huawei_traffic_filter_to_cisco(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_h3c_packet_filter_to_cisco(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_cisco_access_group_to_h3c(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_ruijie_access_group_to_h3c(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_cisco_named_acl_header_to_h3c(stripped)
        if rv is not None:
            return rv

        rv = acl.translate_cisco_numbered_acl(stripped)
        if rv is not None:
            return rv

        rv = sw.translate_to_h3c_switch(stripped, lower, indent, from_vendor, state)
        if rv is not None:
            return rv

        rv = rt.translate_routing_to_h3c(stripped, lower, indent, state)
        if rv is not None:
            return rv

        rv = rt.translate_vrf_to_h3c(stripped, lower, indent)
        if rv is not None:
            return rv

        if lower.startswith("neighbor ") or lower.startswith(" peer "):
            return indent + manual_review_comment(stripped, "h3c", indent)
        if lower.startswith(("route-map ", "route-policy ", "ip prefix-list ", "prefix-list ")):
            return indent + manual_review_comment(stripped, "h3c", indent)
        if lower.startswith(("spanning-tree ", "stp ", "bpduguard", "loopguard", "rootguard")):
            if not (lower.startswith("stp edged-port") or lower.startswith("spanning-tree portfast")):
                return indent + manual_review_comment(stripped, "h3c", indent)

        return indent + stripped

    def _to_ruijie(self, stripped: str, lower: str, indent: str, from_vendor: str, state: Dict):
        rv = mgmt.translate_hostname_to_ruijie(stripped, lower, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_ntp_to_ruijie(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_logging_to_ruijie(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_aaa_to_ruijie(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = mgmt.translate_snmp_to_ruijie(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_huawei_traffic_filter_to_cisco(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_h3c_packet_filter_to_cisco(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = acl.translate_cisco_access_group_to_ruijie(stripped, lower, indent, from_vendor)
        if rv is not None:
            return rv

        rv = sw.translate_to_ruijie_switch(stripped, lower, indent, from_vendor, state)
        if rv is not None:
            return rv

        rv = rt.translate_routing_to_ruijie(stripped, lower, indent, state)
        if rv is not None:
            return rv

        rv = rt.translate_vrf_to_ruijie(stripped, lower, indent)
        if rv is not None:
            return rv

        if lower.startswith("switchport "):
            return indent + stripped
        if lower.startswith(("route-map ", "route-policy ", "ip prefix-list ", "prefix-list ")):
            return indent + manual_review_comment(stripped, "ruijie", indent)
        fv = (from_vendor or "").lower()
        if fv in ("cisco", "huawei", "h3c"):
            return manual_review_comment(stripped, "ruijie", indent)
        return stripped

    def _translate_acl_to_huawei(self, stripped: str, lower: str, state: Dict):
        m = re.match(r"access-list\s+(\d+)\s+(permit|deny)\s+(\S+)\s+(.+)", lower)
        if not m:
            return None

        if "object-group" in lower:
            return [manual_review_comment(stripped, "huawei")]

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
        if source.lower() == "host" and tokens:
            source = tokens.pop(0)
        elif source != "any" and tokens:
            source_wildcard = tokens.pop(0)
        if tokens:
            destination = tokens.pop(0)
        if destination.lower() == "host" and tokens:
            destination = tokens.pop(0)
        elif destination != "any" and tokens:
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

    def _check_flush_secpol_at_line_boundary(self, indent: str, state: Dict):
        return fw.check_flush_secpol_at_line_boundary(indent, state)

    def _flush_pending_state(self, state: Dict, to_vendor: str) -> Optional[List[str]]:
        result = []
        if state.get("_in_secpol"):
            pending = state.get("_secpol")
            seen_rule = state.pop("_secpol_seen_rule", False)
            state["_in_secpol"] = False
            state["_secpol"] = None
            if pending and pending.get("name"):
                if pending.get("action"):
                    result.append(fw._render_policy(pending))
                else:
                    result.append(manual_review_comment(
                        f"security-policy name={pending['name']} incomplete: missing action/destination/service",
                        to_vendor,
                    ))
            elif not seen_rule:
                result.append(manual_review_comment(
                    "security-policy (incomplete: no rule defined)",
                    to_vendor,
                ))
        return result if result else None