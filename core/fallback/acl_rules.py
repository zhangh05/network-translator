# -*- coding: utf-8 -*-
"""ACL and interface-binding translation rules for the fallback translator."""

import re
from typing import Optional, Union, List


def manual_review_comment(stripped: str, to_vendor: str, indent: str = "") -> str:
    prefix = "!" if (to_vendor or "").lower() in ("cisco", "ruijie") else "#"
    return indent + f"{prefix} MANUAL_REVIEW unsupported source command: {stripped}"


def _direction_to_cisco(direction: str) -> str:
    return "in" if direction.lower() == "inbound" else "out"


def _direction_to_cisco_qos(direction: str) -> str:
    return "input" if direction.lower() == "inbound" else "output"


# ─────────────────────────────────────────────────────────────────────────────
# Huawei traffic-filter / H3C packet-filter → Cisco ip access-group
# ─────────────────────────────────────────────────────────────────────────────

def translate_huawei_traffic_filter_to_cisco(
    stripped: str, lower: str, indent: str, from_vendor: str
) -> Optional[str]:
    if from_vendor.lower() not in ("huawei", "h3c"):
        return None
    m = re.match(r"traffic-filter\s+(inbound|outbound)\s+acl(?:\s+name)?\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        return indent + f"ip access-group {m.group(2)} {_direction_to_cisco(m.group(1))}"
    return None


def translate_h3c_packet_filter_to_cisco(
    stripped: str, lower: str, indent: str, from_vendor: str
) -> Optional[str]:
    if from_vendor.lower() != "h3c":
        return None
    m = re.match(r"packet-filter\s+(\S+)\s+(inbound|outbound)", stripped, re.IGNORECASE)
    if m:
        return indent + f"ip access-group {m.group(1)} {_direction_to_cisco(m.group(2))}"
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Cisco ip access-group → Huawei / H3C / Ruijie
# ─────────────────────────────────────────────────────────────────────────────

def translate_cisco_access_group_to_huawei(
    stripped: str, lower: str, indent: str, from_vendor: str
) -> Optional[str]:
    if from_vendor.lower() != "cisco":
        return None
    m = re.match(r"ip\s+access-group\s+(\S+)\s+(in|out)\b", stripped, re.IGNORECASE)
    if m:
        direction = "inbound" if m.group(2) == "in" else "outbound"
        return indent + f"traffic-filter {direction} acl {m.group(1)}"
    return None


def translate_cisco_access_group_to_h3c(
    stripped: str, lower: str, indent: str, from_vendor: str
) -> Optional[str]:
    if from_vendor.lower() != "cisco":
        return None
    m = re.match(r"ip\s+access-group\s+(\S+)\s+(in|out)\b", stripped, re.IGNORECASE)
    if m:
        direction = "inbound" if m.group(2) == "in" else "outbound"
        return indent + f"packet-filter {m.group(1)} {direction}"
    return None


def translate_cisco_access_group_to_ruijie(
    stripped: str, lower: str, indent: str, from_vendor: str
) -> Optional[str]:
    if from_vendor.lower() != "cisco":
        return None
    m = re.match(r"ip\s+access-group\s+(\S+)\s+(in|out)\b", stripped, re.IGNORECASE)
    if m:
        return indent + f"ip access-group {m.group(1)} {m.group(2)}"
    return None


def translate_ruijie_access_group_to_huawei(
    stripped: str, lower: str, indent: str, from_vendor: str
) -> Optional[str]:
    if from_vendor.lower() != "ruijie":
        return None
    m = re.match(r"ip\s+access-group\s+(\S+)\s+(in|out)\b", stripped, re.IGNORECASE)
    if m:
        direction = "inbound" if m.group(2) == "in" else "outbound"
        return indent + f"traffic-filter {direction} acl {m.group(1)}"
    return None


def translate_ruijie_access_group_to_h3c(
    stripped: str, lower: str, indent: str, from_vendor: str
) -> Optional[str]:
    if from_vendor.lower() != "ruijie":
        return None
    m = re.match(r"ip\s+access-group\s+(\S+)\s+(in|out)\b", stripped, re.IGNORECASE)
    if m:
        direction = "inbound" if m.group(2) == "in" else "outbound"
        return indent + f"packet-filter {m.group(1)} {direction}"
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Huawei traffic-policy (QoS) → Cisco service-policy
# ─────────────────────────────────────────────────────────────────────────────

def translate_huawei_traffic_policy_to_cisco(
    stripped: str, lower: str, indent: str, from_vendor: str
) -> Optional[str]:
    if from_vendor.lower() not in ("huawei", "h3c"):
        return None
    m = re.match(r"traffic-policy\s+(\S+)\s+(inbound|outbound)", stripped, re.IGNORECASE)
    if m:
        return indent + f"service-policy {_direction_to_cisco_qos(m.group(2))} {m.group(1)}"
    return None


# ─────────────────────────────────────────────────────────────────────────────
# ACL rule translation helpers
# ─────────────────────────────────────────────────────────────────────────────

ACL_KEYWORDS = {
    "source", "destination", "source-port", "destination-port",
    "time-range", "vpn-instance", "logging", "eq", "neq", "gt", "lt",
}


def _format_cisco_acl_endpoint(value: str, wildcard: Optional[str]) -> str:
    if not value or value.lower() == "any":
        return "any"
    if wildcard in (None, ""):
        return value
    if wildcard == "0":
        return "host " + value
    return value + " " + wildcard


def _is_acl_keyword(token: str) -> bool:
    return token.lower() in ACL_KEYWORDS


# ─────────────────────────────────────────────────────────────────────────────
# Huawei ACL rule → Cisco
# ─────────────────────────────────────────────────────────────────────────────

def translate_huawei_acl_rule_to_cisco(
    stripped: str, lower: str, indent: str
) -> Optional[Union[str, List[str]]]:
    m = re.match(r"rule\s+(\d+)?\s*(permit|deny)\s+(ip|tcp|udp|icmp|any)\s+(.+)", stripped, re.IGNORECASE)
    if not m:
        return None

    rest = m.group(4)
    lower_rest = rest.lower()

    complex_kw = (
        "object-group", "object ", "evaluate", "reflect", "dynamic",
        "time-range", "vpn-instance", "source-port", "logging",
    )
    if any(kw in lower_rest for kw in complex_kw):
        return indent + manual_review_comment(stripped, "cisco", indent)

    port_ops = ("gt", "lt", "neq", "range")
    tokens_rest = rest.split()
    for i, tok in enumerate(tokens_rest):
        if tok.lower() in port_ops and i + 1 < len(tokens_rest):
            return indent + manual_review_comment(stripped, "cisco", indent)

    seq = m.group(1) or ""
    action = m.group(2).lower()
    protocol = m.group(3).lower()

    if protocol == "any":
        protocol = "ip"

    tokens = rest.split()
    source, source_wc = "any", None
    destination, destination_wc = "any", None
    port = None

    idx = 0
    while idx < len(tokens):
        key = tokens[idx].lower()
        if key == "source" and idx + 1 < len(tokens):
            source = tokens[idx + 1]
            idx += 2
            if source.lower() != "any" and idx < len(tokens) and not _is_acl_keyword(tokens[idx]):
                source_wc = tokens[idx]
                idx += 1
            continue
        if key == "destination" and idx + 1 < len(tokens):
            destination = tokens[idx + 1]
            idx += 2
            if destination.lower() != "any" and idx < len(tokens) and not _is_acl_keyword(tokens[idx]):
                destination_wc = tokens[idx]
                idx += 1
            continue
        if key in ("destination-port", "source-port") and idx + 2 < len(tokens):
            if tokens[idx + 1].lower() == "eq":
                port = tokens[idx + 2]
            idx += 3
            continue
        idx += 1

    parts = []
    if seq:
        parts.append(seq)
    parts.extend([action, protocol])
    parts.append(_format_cisco_acl_endpoint(source, source_wc))
    parts.append(_format_cisco_acl_endpoint(destination, destination_wc))
    if port:
        parts.extend(["eq", port])
    return indent + " ".join(parts)


def translate_huawei_named_acl_header_to_cisco(stripped: str) -> Optional[str]:
    m = re.match(r"acl\s+name\s+(\S+)(?:\s+\S+)?", stripped, re.IGNORECASE)
    if m:
        return f"ip access-list extended {m.group(1)}"
    m = re.match(r"acl\s+number\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        return f"ip access-list extended {m.group(1)}"
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Cisco numbered ACL → Huawei / H3C
# ─────────────────────────────────────────────────────────────────────────────

def _build_acl_rest(action: str, protocol: str, rest: str) -> str:
    tokens = rest.split()
    source, source_wc = "any", None
    destination, destination_wc = "any", None
    port = None

    if tokens:
        source = tokens.pop(0)
    if source.lower() == "host" and tokens:
        source = tokens.pop(0)
    elif source != "any" and tokens:
        source_wc = tokens.pop(0)
    if tokens:
        destination = tokens.pop(0)
    if destination.lower() == "host" and tokens:
        destination = tokens.pop(0)
    elif destination != "any" and tokens:
        destination_wc = tokens.pop(0)
    if len(tokens) >= 2 and tokens[0].lower() == "eq":
        port = tokens[1]

    parts = [f"rule {action} {protocol}"]
    parts.extend(["source", source])
    if source_wc:
        parts.append(source_wc)
    parts.extend(["destination", destination])
    if destination_wc:
        parts.append(destination_wc)
    if port:
        parts.extend(["destination-port", "eq", port])
    return " ".join(parts)


def translate_cisco_numbered_acl(
    stripped: str, to_vendor: str = "huawei"
) -> Optional[Union[str, List[str]]]:
    m = re.match(r"access-list\s+(\d+)\s+(permit|deny)\s+(\S+)\s+(.+)", stripped, re.IGNORECASE)
    if not m:
        return None
    acl_id, action, protocol, rest = m.groups()
    out = [f"acl number {acl_id}", " " + _build_acl_rest(action, protocol, rest)]
    return out


def translate_h3c_packet_filter_to_huawei(
    stripped: str, lower: str, indent: str, from_vendor: str
) -> Optional[str]:
    if from_vendor.lower() != "h3c":
        return None
    m = re.match(r"packet-filter\s+(\S+)\s+(inbound|outbound)", stripped, re.IGNORECASE)
    if m:
        direction = "inbound" if m.group(2).lower() == "inbound" else "outbound"
        return indent + f"traffic-filter {direction} acl {m.group(1)}"
    return None


def translate_huawei_traffic_filter_to_h3c(
    stripped: str, lower: str, indent: str, from_vendor: str
) -> Optional[str]:
    if from_vendor.lower() not in ("huawei",):
        return None
    m = re.match(r"traffic-filter\s+(inbound|outbound)\s+acl(?:\s+name)?\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        return indent + f"packet-filter {m.group(2)} {m.group(1)}"
    return None


def translate_cisco_named_acl_header_to_huawei(stripped: str) -> Optional[str]:
    m = re.match(r"ip\s+access-list\s+(extended|standard)\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        acl_type = "advanced" if m.group(1).lower() == "extended" else "basic"
        return f"acl name {m.group(2)} {acl_type}"
    return None


def translate_cisco_named_acl_header_to_h3c(stripped: str) -> Optional[str]:
    m = re.match(r"ip\s+access-list\s+(extended|standard)\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        acl_type = "advanced" if m.group(1).lower() == "extended" else "basic"
        return f"acl name {m.group(2)} {acl_type}"
    return None


def translate_cisco_named_acl_header_to_cisco(stripped: str) -> Optional[str]:
    m = re.match(r"ip\s+access-list\s+(extended|standard)\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        return stripped
    return None


def translate_ruijie_access_group_to_cisco(
    stripped: str, lower: str, indent: str, from_vendor: str
) -> Optional[str]:
    if from_vendor.lower() != "ruijie":
        return None
    m = re.match(r"ip\s+access-group\s+(\S+)\s+(in|out)\b", stripped, re.IGNORECASE)
    if m:
        return indent + f"ip access-group {m.group(1)} {m.group(2)}"
    return None