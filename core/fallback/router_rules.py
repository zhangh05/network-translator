# -*- coding: utf-8 -*-
"""ROUTER-domain translation rules for the fallback translator."""

import re
from typing import List, Optional, Union

from core.fallback.common import (
    manual_review_comment,
)

ROUTEMAP_KEYWORDS = ("route-map ", "route-policy ", "ip prefix-list ", "prefix-list ")


def translate_static_route(stripped: str, lower: str, indent: str, to_vendor: str) -> Optional[Union[str, List[str]]]:
    m = re.match(r"ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$", stripped, re.IGNORECASE)
    if m:
        route = f"ip route-static {m.group(1)} {m.group(2)} {m.group(3)}"
        if m.group(4):
            prefix = "#" if to_vendor not in ("cisco", "ruijie") else "!"
            return [route, f"{prefix} MANUAL_REVIEW route options: {m.group(4)}"]
        return route
    if lower.startswith("ip route-static "):
        m = re.match(r"ip route-static\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$", stripped, re.IGNORECASE)
        if m:
            route = f"ip route-static {m.group(1)} {m.group(2)} {m.group(3)}"
            if m.group(4):
                prefix = "#" if to_vendor not in ("cisco", "ruijie") else "!"
                return [route, f"{prefix} MANUAL_REVIEW route options: {m.group(4)}"]
            return route
    return None


def translate_static_route_to_cisco(stripped: str, lower: str, indent: str) -> Optional[Union[str, List[str]]]:
    m = re.match(r"ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$", stripped, re.IGNORECASE)
    if m:
        route = f"ip route {m.group(1)} {m.group(2)} {m.group(3)}"
        if m.group(4):
            return [route, f"! MANUAL_REVIEW route options: {m.group(4)}"]
        return route
    return None


def translate_routing_to_huawei(stripped: str, lower: str, indent: str, state: dict) -> Optional[Union[str, List[str]]]:
    # Static route
    rv = translate_static_route(stripped, lower, indent, "huawei")
    if rv is not None:
        return rv

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
    if lower.startswith("area "):
        if re.search(r"\b(stub|nssa|virtual-link|authentication)\b", lower):
            return indent + manual_review_comment(stripped, "huawei", indent)
        return indent + stripped
    if lower.startswith("network ") and not state.get("in_bgp"):
        return indent + stripped
    if lower.startswith("passive-interface "):
        return indent + "silent-interface " + stripped.split(maxsplit=1)[1]
    if lower.startswith("no passive-interface "):
        return indent + "undo silent-interface " + stripped.split(maxsplit=2)[2]
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
    if lower.startswith("neighbor ") and re.search(r"\b(password|cipher)\s+\S+", lower):
        redacted = re.sub(r"(password|cipher)\s+.+", r"\1 <redacted>", stripped)
        return indent + manual_review_comment(redacted, "huawei", indent)
    if lower.startswith("neighbor ") or lower.startswith("peer "):
        return indent + manual_review_comment(stripped, "huawei", indent)
    if lower.startswith("ipv4-family unicast"):
        return None
    return None


def translate_routing_to_cisco(stripped: str, lower: str, indent: str, state: dict) -> Optional[Union[str, List[str]]]:
    # OSPF
    if lower.startswith("ospf ") and "router-id" in lower:
        m = re.match(r"ospf\s+(\S+)\s+router-id\s+(\S+)", lower)
        if m:
            return [f"router ospf {m.group(1)}", f" router-id {m.group(2)}"]
    if lower.startswith("ospf "):
        m = re.match(r"ospf\s+(\S+)", lower)
        return f"router ospf {m.group(1)}" if m else stripped
    if lower.startswith("area "):
        if re.search(r"\b(stub|nssa|virtual-link|authentication)\b", lower):
            return indent + manual_review_comment(stripped, "cisco", indent)
        return indent + stripped
    if lower.startswith("network "):
        return indent + stripped
    if lower.startswith("router-id "):
        return indent + stripped
    if lower.startswith("silent-interface"):
        return indent + "passive-interface " + stripped.split(maxsplit=1)[1]
    if lower.startswith("undo silent-interface"):
        return indent + "no passive-interface " + stripped.split(maxsplit=2)[2]

    # OSPF redistribution/opts — must MANUAL_REVIEW
    if re.match(r"(default-route-advertise|import-route|redistribute)", lower):
        return indent + manual_review_comment(stripped, "cisco", indent)

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
    if (lower.startswith("neighbor ") or lower.startswith("peer ")) and ("password" in lower or "cipher" in lower):
        redacted = re.sub(r"(password|cipher)\s+.+", r"\1 <redacted>", stripped)
        return indent + manual_review_comment(redacted, "cisco", indent)
    if lower.startswith("neighbor ") or lower.startswith("peer "):
        return indent + manual_review_comment(stripped, "cisco", indent)

    # Static route
    m = re.match(r"ip route-static\s+vpn-instance\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        return f"ip route vrf {m.group(1)} {m.group(2)} {m.group(3)} {m.group(4)}"
    m = re.match(r"ip route-static\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$", stripped, re.IGNORECASE)
    if m:
        route = f"ip route {m.group(1)} {m.group(2)} {m.group(3)}"
        if m.group(4):
            return [route, f"! MANUAL_REVIEW route options: {m.group(4)}"]
        return route
    return None


def translate_routing_to_h3c(stripped: str, lower: str, indent: str, state: dict) -> Optional[Union[str, List[str]]]:
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
    rv = translate_static_route(stripped, lower, indent, "h3c")
    if rv is not None:
        return rv
    return None


def translate_routing_to_ruijie(stripped: str, lower: str, indent: str, state: dict) -> Optional[Union[str, List[str]]]:
    # OSPF
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
        return indent + "passive-interface " + stripped.split(maxsplit=1)[1]
    if lower.startswith("undo silent-interface"):
        return indent + "no passive-interface " + stripped.split(maxsplit=2)[2]

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
        return f" neighbor {m.group(1)} remote-as {m.group(2)}"
    m = re.match(r"peer\s+(\S+)\s+as-number\s+(\S+)", lower)
    if m:
        return stripped
    if lower.startswith("ipv4-family unicast"):
        return None

    # Static route
    m = re.match(r"ip route-static\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$", stripped, re.IGNORECASE)
    if m:
        route = f"ip route {m.group(1)} {m.group(2)} {m.group(3)}"
        if m.group(4):
            return [route, f"! MANUAL_REVIEW route options: {m.group(4)}"]
        return route
    if lower.startswith("ip route "):
        return stripped
    return None


def translate_vrf_to_huawei(stripped: str, lower: str, indent: str) -> Optional[str]:
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
    return None


def translate_vrf_to_cisco(stripped: str, lower: str, indent: str) -> Optional[str]:
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
    return None


def translate_vrf_to_h3c(stripped: str, lower: str, indent: str) -> Optional[str]:
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
    return None


def translate_vrf_to_ruijie(stripped: str, lower: str, indent: str) -> Optional[str]:
    m = re.match(r"vrf\s+definition\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        return f"vrf definition {m.group(1)}"
    if lower.startswith("route-distinguisher "):
        return indent + stripped
    if lower.startswith("vpn-target "):
        return indent + stripped
    if lower.startswith("rd "):
        return indent + stripped
    if lower.startswith("route-target "):
        return indent + stripped
    return None


def catch_all_manual_review(stripped: str, lower: str, indent: str, to_vendor: str) -> str:
    if lower.startswith(ROUTEMAP_KEYWORDS):
        return indent + manual_review_comment(stripped, to_vendor, indent)
    return indent + manual_review_comment(stripped, to_vendor, indent)


ROUTEMAP_SKIP_KEYWORDS = (
    "continue", "call ", "on ", "add", "set ", "match ",
)


def translate_cisco_route_map_to_huawei(stripped: str, lower: str, indent: str) -> Optional[Union[str, List[str]]]:
    m = re.match(r"route-map\s+(\S+)\s+(permit|deny)\s+(\d+)(?:\s+(.+))?$", stripped, re.IGNORECASE)
    if not m:
        return None
    name, action, seq, rest = m.groups()
    if rest:
        first_word = rest.split()[0].lower() if rest.split() else ""
        if any(rest.lower().startswith(kw) for kw in ROUTEMAP_SKIP_KEYWORDS):
            return None
        return [f"route-policy {name} {action} node {seq}", manual_review_comment(f"route-map body: {rest}", "huawei", indent)]
    return f"route-policy {name} {action} node {seq}"


def translate_huawei_route_policy_to_cisco(stripped: str, lower: str, indent: str) -> Optional[Union[str, List[str]]]:
    m = re.match(r"route-policy\s+(\S+)\s+(permit|deny)\s+node\s+(\d+)(?:\s+(.+))?$", stripped, re.IGNORECASE)
    if not m:
        return None
    name, action, seq, rest = m.groups()
    if rest:
        if any(rest.lower().startswith(kw) for kw in ROUTEMAP_SKIP_KEYWORDS):
            return None
        return [f"route-map {name} {action} {seq}", manual_review_comment(f"route-policy body: {rest}", "cisco", indent)]
    return f"route-map {name} {action} {seq}"


def translate_route_map_match_to_huawei(stripped: str, lower: str, indent: str) -> Optional[str]:
    m = re.match(r"match\s+ip\s+address\s+(prefix-list|\S+)(?:\s+(\S+))?", stripped, re.IGNORECASE)
    if m:
        target, name = m.group(1), m.group(2)
        if target.lower() == "prefix-list" or (name and name.lower() == "prefix-list"):
            return None
        acl_name = name if name else target
        return indent + f"if-match acl {acl_name}"
    return None


def translate_route_policy_match_to_cisco(stripped: str, lower: str, indent: str) -> Optional[str]:
    m = re.match(r"if-match\s+acl\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        return indent + f"match ip address {m.group(1)}"
    return None


def translate_route_map_set_to_huawei(stripped: str, lower: str, indent: str) -> Optional[str]:
    m = re.match(r"set\s+local-preference\s+(\d+)", lower)
    if m:
        return f"apply local-preference {m.group(1)}"
    return None


def translate_route_policy_set_to_cisco(stripped: str, lower: str, indent: str) -> Optional[str]:
    m = re.match(r"apply\s+local-preference\s+(\d+)", lower)
    if m:
        return f"set local-preference {m.group(1)}"
    return None