# -*- coding: utf-8 -*-
"""FIREWALL-domain translation rules for the fallback translator."""

import re
from typing import Optional, Union

from core.fallback.common import manual_review_comment

ROUTEMAP_KEYWORDS = ("route-map ", "route-policy ", "ip prefix-list ", "prefix-list ")
STP_CATCH_ALL = ("spanning-tree ", "stp ", "bpduguard", "loopguard", "rootguard")


def netmask_to_prefixlen(netmask: str) -> str:
    parts = netmask.split(".")
    if len(parts) != 4:
        return netmask
    try:
        binary = "".join(f"{int(p):08b}" for p in parts)
        cnt = binary.count("1")
        return str(cnt)
    except (ValueError, TypeError):
        return netmask


def prefixlen_to_netmask(prefixlen: str) -> str:
    try:
        n = int(prefixlen)
        if n < 0 or n > 32:
            return prefixlen
        mask = ((1 << n) - 1) << (32 - n) if n > 0 else 0
        return ".".join(str((mask >> (24 - i * 8)) & 0xFF) for i in range(4))
    except (ValueError, TypeError):
        return str(prefixlen)


def translate_to_hillstone_firewall(stripped: str, lower: str, indent: str, from_vendor: str, state: dict) -> Optional[Union[str, list]]:
    if re.search(r"(cipher|password)\s+\S+", lower):
        return "# MANUAL_REVIEW <redacted> (secret/cipher)"
    if (from_vendor or "").lower() == "hillstone":
        return stripped

    # Huawei USG security-policy multi-line block
    if state.get("_in_secpol"):
        if not indent:
            return None
        m = re.match(r"rule\s+name\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            state["_secpol_seen_rule"] = True
            secpol = state.get("_secpol")
            state["_secpol"] = {"name": m.group(1)}
            if secpol and secpol.get("name"):
                if secpol.get("action"):
                    return _render_policy(secpol)
                else:
                    return manual_review_comment(
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
                        name = secpol.get("name", "UNNAMED")
                        return f"# MANUAL_REVIEW security-policy rule={name} multi-{key.replace('_','-')}: {m.group(1)} (only first preserved)"
                    secpol[key] = m.group(1)
                return None

        m = re.match(r"action\s+(permit|deny)", stripped, re.IGNORECASE)
        if m:
            pending = state.get("_secpol", {})
            pending["action"] = m.group(1)
            state["_secpol"] = None
            return _render_policy(pending)

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
        m = re.match(r"address\s+(\d+)\s+(\S+)\s+mask\s+(\d+)", stripped, re.IGNORECASE)
        if m:
            name = state.pop("_addr_set")
            ip = m.group(2)
            mask = prefixlen_to_netmask(m.group(3))
            return f"address {name} {ip} {mask}"
        m = re.match(r"address\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", stripped)
        if m:
            ip = m.group(2)
            third = m.group(3)
            prefix = netmask_to_prefixlen(third)
            name = state.pop("_addr_set")
            if prefix != third:
                return f"address {name} {ip} {third}"
            else:
                return manual_review_comment(
                    f"ip address-set {name} range {ip} {third}", "hillstone",
                )
        m = re.match(r"address\s+(\d+)\s+(\S+)\s+mask\s+host", stripped, re.IGNORECASE)
        if m:
            name = state.pop("_addr_set")
            ip = m.group(2)
            return f"address {name} {ip} host"
        name = state.pop("_addr_set")
        return manual_review_comment(
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
        m = re.match(r"service\s+(\d+)\s+protocol\s+(\S+)\s*$", stripped, re.IGNORECASE)
        if m:
            name = state.pop("_svc_set")
            proto = m.group(2)
            return f"service {name} {proto}"
        name = state.pop("_svc_set")
        return manual_review_comment(
            f"ip service-set {name} sub-command: {stripped}", "hillstone",
        )

    # Hillstone service object (passthrough)
    m = re.match(r"service\s+(\S+)\s+(\S+)\s+dst-port\s+(\S+)", lower)
    if m and from_vendor == "hillstone":
        return stripped

    # DPtech single-line policy -> Hillstone
    m = re.match(
        r"security-policy\s+name\s+(\S+)\s+source-zone\s+(\S+)\s+destination-zone\s+(\S+)\s+(?:source-address\s+(\S+)\s+)?destination-address\s+(\S+)\s+service\s+(\S+)\s+action\s+(permit|deny)",
        stripped,
        re.IGNORECASE,
    )
    if m:
        name, src_zone, dst_zone, src_addr, dst_addr, svc, action = m.groups()
        return f"policy {name} from {src_zone} to {dst_zone} source {src_addr or 'any'} destination {dst_addr} service {svc} action {action}"

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

    return manual_review_comment(stripped, "hillstone", indent)


def check_flush_secpol_at_line_boundary(indent: str, state: dict) -> Optional[list]:
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
            output.append(_render_policy(pending))
        else:
            output.append(manual_review_comment(
                f"security-policy name={pending['name']} incomplete: missing action/destination/service",
                "hillstone",
            ))
    elif not seen_rule:
        output.append(manual_review_comment(
            "security-policy (incomplete: no rule defined)",
            "hillstone",
        ))
    return output


def _render_policy(rule: dict) -> str:
    name = rule.get("name", "UNNAMED")
    src_zone = rule.get("src_zone", "any")
    dst_zone = rule.get("dst_zone", "any")
    src_addr = rule.get("src_addr", "any")
    dst_addr = rule.get("dst_addr", "any")
    svc = rule.get("service", "any")
    action = rule.get("action", "permit")
    return f"policy {name} from {src_zone} to {dst_zone} source {src_addr} destination {dst_addr} service {svc} action {action}"


def translate_to_huawei_usg_firewall(stripped: str, lower: str, indent: str, from_vendor: str, state: dict) -> Optional[Union[str, list]]:
    if re.search(r"(cipher|password)\s+\S+", lower):
        return "# MANUAL_REVIEW <redacted> (secret/cipher)"
    if (from_vendor or "").lower() == "huawei_usg":
        return stripped

    # Topsec zone (zone name <zone>)
    m = re.match(r"zone\s+name\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        return f"security-zone name {m.group(1)}"

    # Zone (Hillstone, DPtech plain zone <zone>)
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
        prefix = netmask_to_prefixlen(mask)
        return [f"ip address-set {name} type object", f" address 0 {ip} mask {prefix}"]

    # Address object (DPtech -> Huawei USG multi-line)
    m = re.match(r"object\s+address\s+(\S+)\s+(\S+)\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        name, ip, mask = m.groups()
        prefix = netmask_to_prefixlen(mask)
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
        name = state.pop("_addr_set")
        return manual_review_comment(
            f"ip address-set {name} sub-command: {stripped}", "huawei_usg",
        )

    # Service object (Hillstone flat -> Huawei USG multi-line)
    m = re.match(r"service\s+(\S+)\s+(\S+)\s+dst-port\s+(\S+)", stripped, re.IGNORECASE)
    if m and from_vendor == "hillstone":
        name, proto, port = m.groups()
        return [f"ip service-set {name} type object", f" service 0 protocol {proto} destination-port {port}"]

    # Service ANY ip (Hillstone -> Huawei USG: protocol ip with no port = any)
    m = re.match(r"service\s+(\S+)\s+ip\s*$", lower)
    if m and from_vendor == "hillstone":
        name = m.group(1)
        return [f"ip service-set {name} type object", f" service 0 protocol ip"]

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
        name = state.pop("_svc_set")
        return manual_review_comment(
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

    return manual_review_comment(stripped, "huawei_usg", indent)


def translate_firewall_manual_review(stripped: str, indent: str, to_vendor: str, from_vendor: str) -> str:
    if (from_vendor or "").lower() == (to_vendor or "").lower():
        return indent + stripped
    return manual_review_comment(stripped, to_vendor, indent)