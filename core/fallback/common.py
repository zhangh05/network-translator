# -*- coding: utf-8 -*-
"""Shared helper functions for fallback rule modules."""

import re
from typing import List, Optional


def manual_review_comment(stripped: str, to_vendor: str, indent: str = "") -> str:
    prefix = "!" if (to_vendor or "").lower() in ("cisco", "ruijie") else "#"
    redacted = stripped
    for pat, repl in (
        (r"(password\s+)\S+", r"\1<redacted>"),
        (r"(secret\s+)\S+", r"\1<redacted>"),
        (r"(cipher\s+)\S+", r"\1<redacted>"),
        (r"(shared-key\s+)\S+", r"\1<redacted>"),
        (r"(community\s+)\S+", r"\1<redacted>"),
        (r"(key\s+)\S+", r"\1<redacted>"),
    ):
        redacted = re.sub(pat, repl, redacted, flags=re.IGNORECASE)
    return indent + f"{prefix} MANUAL_REVIEW unsupported source command: {redacted}"


def parse_vlan_list(value: str) -> List:
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


def format_vlans_cisco(vlans: list) -> str:
    if not vlans:
        return ""
    groups = [[vlans[0], vlans[0]]]
    for v in vlans[1:]:
        if isinstance(v, int) and isinstance(groups[-1][1], int) and v == groups[-1][1] + 1:
            groups[-1][1] = v
        else:
            groups.append([v, v])
    return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in groups)


def format_vlans_huawei_batch(vlans: list) -> str:
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


def normalize_vlan_list(value: str) -> str:
    return value.replace(",", " ")


def normalize_vlan_list_cisco(value: str) -> str:
    normalized = re.sub(r"(?i)\b(\d+)\s+to\s+(\d+)\b", r"\1-\2", value)
    return ",".join(part for part in re.split(r"[\s,]+", normalized.strip()) if part)


def normalize_interface_to_huawei(name: str) -> str:
    normalized = re.sub(r"(?i)^Vlan-interface(\d+)$", r"Vlanif\1", name)
    normalized = re.sub(r"(?i)^Port-channel(\d+)$", r"Eth-Trunk\1", normalized)
    normalized = re.sub(r"(?i)^AggregatePort\s*(\d+)$", r"Eth-Trunk\1", normalized)
    normalized = re.sub(r"(?i)^TenGigabitEthernet", "XGigabitEthernet", normalized)
    normalized = re.sub(r"(?i)^Bridge-Aggregation(\d+)$", r"Eth-Trunk\1", normalized)
    return normalized


def normalize_interface_to_h3c(name: str) -> str:
    normalized = re.sub(r"(?i)^Port-channel(\d+)$", r"Bridge-Aggregation\1", name)
    normalized = re.sub(r"(?i)^AggregatePort\s*(\d+)$", r"Bridge-Aggregation\1", normalized)
    normalized = re.sub(r"(?i)^Vlanif(\d+)$", r"Vlan-interface\1", normalized)
    normalized = re.sub(r"(?i)^Vlan(\d+)$", r"Vlan-interface\1", normalized)
    normalized = re.sub(r"(?i)^TenGigabitEthernet", "XGigabitEthernet", normalized)
    return normalized


def normalize_interface_to_cisco(name: str) -> Optional[str]:
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


def normalize_interface_to_ruijie(name: str) -> Optional[str]:
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