# -*- coding: utf-8 -*-
"""FIREWALL-domain translation rules for the fallback translator."""

import re
from typing import List, Optional, Union

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

    if re.search(r"\b(add\s+interface|bind\s+interface|interface\s+bind)\b", lower):
        return manual_review_comment(stripped, "hillstone", indent)

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
    if state.get("_svc_set") is not None:
        rv = translate_huawei_usg_service_to_hillstone(stripped, lower, indent, state)
        if rv is not None:
            return rv

    m = re.match(r"ip\s+service-set\s+(\S+)\s+type\s+object", stripped, re.IGNORECASE)
    if m:
        state["_svc_set"] = m.group(1)
        return None

    # Hillstone service object (passthrough)
    m = re.match(r"service\s+(\S+)\s+(\S+)\s+dst-port\s+(\S+)", lower)
    if m and from_vendor == "hillstone":
        return stripped

    # Topsec service object -> Hillstone
    rv = translate_topsec_service_to_hillstone(stripped, lower, indent)
    if rv is not None:
        return rv

    # DPtech single-line policy -> Hillstone (requires source-address, no defaulting)
    m = re.match(
        r"security-policy\s+name\s+(\S+)\s+source-zone\s+(\S+)\s+destination-zone\s+(\S+)\s+source-address\s+(\S+)\s+destination-address\s+(\S+)\s+service\s+(\S+)\s+action\s+(permit|deny)",
        stripped,
        re.IGNORECASE,
    )
    if m:
        name, src_zone, dst_zone, src_addr, dst_addr, svc, action = m.groups()
        return f"policy {name} from {src_zone} to {dst_zone} source {src_addr} destination {dst_addr} service {svc} action {action}"

    # DPtech single-line policy missing source-address -> MANUAL_REVIEW (no implicit "any")
    m = re.match(
        r"security-policy\s+name\s+(\S+)\s+source-zone\s+(\S+)\s+destination-zone\s+(\S+)\s+destination-address\s+(\S+)\s+service\s+(\S+)\s+action\s+(permit|deny)",
        stripped,
        re.IGNORECASE,
    )
    if m:
        return manual_review_comment(
            f"security-policy name={m.group(1)}: missing source-address (DPtech default-any semantics not confirmed)",
            "hillstone",
        )

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

    # DPtech multi-line security-policy block
    if state.get("_in_dptech_secpol"):
        if not indent:
            state["_in_dptech_secpol"] = False
            state.pop("_dptech_secpol", None)
            state["_dptech_secpol_seen_rule"] = False
        else:
            m = re.match(r"source-zone\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                state.setdefault("_dptech_secpol", {})["src_zone"] = m.group(1)
                return None
            m = re.match(r"destination-zone\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                state.setdefault("_dptech_secpol", {})["dst_zone"] = m.group(1)
                return None
            m = re.match(r"source-address\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                state.setdefault("_dptech_secpol", {})["src_addr"] = m.group(1)
                return None
            m = re.match(r"destination-address\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                state.setdefault("_dptech_secpol", {})["dst_addr"] = m.group(1)
                return None
            m = re.match(r"service\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                state.setdefault("_dptech_secpol", {})["service"] = m.group(1)
                return None
            m = re.match(r"action\s+(permit|deny)", stripped, re.IGNORECASE)
            if m:
                dptech_secpol = state.get("_dptech_secpol") or {}
                dptech_secpol["action"] = m.group(1)
                state["_in_dptech_secpol"] = False
                state["_dptech_secpol"] = None
                state["_dptech_secpol_seen_rule"] = False
                all_fields = all(k in dptech_secpol for k in ("src_zone", "dst_zone", "src_addr", "dst_addr", "service", "action"))
                if all_fields:
                    return _render_hillstone_policy(dptech_secpol)
                missing = [f for f in ("src_zone", "dst_zone", "src_addr", "dst_addr", "service") if f not in dptech_secpol]
                return manual_review_comment(
                    f"security-policy name={dptech_secpol.get('name','UNNAMED')} incomplete: missing {', '.join(missing)}",
                    "hillstone",
                )
            name = (state.get("_dptech_secpol") or {}).get("name", "UNNAMED")
            return manual_review_comment(
                f"security-policy name={name} unsupported sub: {stripped}", "hillstone",
            )

    # DPtech security-policy header (multi-line block start)
    m = re.match(r"security-policy\s+name\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        state["_in_dptech_secpol"] = True
        state["_dptech_secpol"] = {"name": m.group(1)}
        state["_dptech_secpol_seen_rule"] = False
        return None

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


def _render_hillstone_policy(rule: dict) -> str:
    name = rule.get("name") or "UNNAMED"
    src_zone = rule.get("src_zone")
    dst_zone = rule.get("dst_zone")
    src_addr = rule.get("src_addr")
    dst_addr = rule.get("dst_addr")
    svc = rule.get("service")
    action = rule.get("action")
    if None in (src_zone, dst_zone, src_addr, dst_addr, svc, action):
        raise ValueError(
            f"_render_hillstone_policy missing fields: "
            f"name={name} src_zone={src_zone} dst_zone={dst_zone} "
            f"src_addr={src_addr} dst_addr={dst_addr} service={svc} action={action}"
        )
    return f"policy {name} from {src_zone} to {dst_zone} source {src_addr} destination {dst_addr} service {svc} action {action}"


def _render_policy(rule: dict) -> str:
    name = rule.get("name") or "UNNAMED"
    src_zone = rule.get("src_zone")
    dst_zone = rule.get("dst_zone")
    src_addr = rule.get("src_addr", "any")
    dst_addr = rule.get("dst_addr", "any")
    svc = rule.get("service", "any")
    action = rule.get("action")
    if None in (src_zone, dst_zone, action):
        raise ValueError(
            f"_render_policy missing required fields: "
            f"name={name} src_zone={src_zone} dst_zone={dst_zone} action={action}"
        )
    return f"policy {name} from {src_zone} to {dst_zone} source {src_addr} destination {dst_addr} service {svc} action {action}"


def _render_huawei_secpol_rule(rule: dict) -> list:
    name = rule.get("name") or "UNNAMED"
    source_zone = rule.get("source_zone")
    dest_zone = rule.get("dest_zone")
    source_address = rule.get("source_address")
    dest_address = rule.get("dest_address")
    svc = rule.get("service")
    action = rule.get("action")
    if None in (source_zone, dest_zone, source_address, dest_address, svc, action):
        raise ValueError(
            f"_render_huawei_secpol_rule missing fields: "
            f"name={name} source_zone={source_zone} dest_zone={dest_zone} "
            f"source_address={source_address} dest_address={dest_address} "
            f"service={svc} action={action}"
        )
    return [
        "security-policy",
        f" rule name {name}",
        f"  source-zone {source_zone}",
        f"  destination-zone {dest_zone}",
        f"  source-address {source_address}",
        f"  destination-address {dest_address}",
        f"  service {svc}",
        f"  action {action}",
    ]


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
        if mask.lower() == "host":
            return manual_review_comment(stripped, "huawei_usg")
        prefix = netmask_to_prefixlen(mask)
        if prefixlen_to_netmask(prefix) != mask:
            return manual_review_comment(stripped, "huawei_usg")
        return [f"ip address-set {name} type object", f" address 0 {ip} mask {prefix}"]

    # Address object (DPtech -> Huawei USG multi-line)
    m = re.match(r"object\s+address\s+(\S+)\s+(\S+)\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        name, ip, mask = m.groups()
        if re.match(r"start$", ip) or re.match(r"end$", ip):
            return manual_review_comment(stripped, "huawei_usg")
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
    rv = translate_hillstone_service_to_huawei_usg(stripped, lower, indent)
    if rv is not None:
        return rv

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

    # Policy (DPtech single-line -> Huawei USG multi-line, requires source-address)
    m = re.match(
        r"security-policy\s+name\s+(\S+)\s+source-zone\s+(\S+)\s+destination-zone\s+(\S+)\s+source-address\s+(\S+)\s+destination-address\s+(\S+)\s+service\s+(\S+)\s+action\s+(permit|deny)",
        stripped,
        re.IGNORECASE,
    )
    if m:
        name, src_zone, dst_zone, src_addr, dst_addr, svc, action = m.groups()
        return [
            "security-policy",
            f" rule name {name}",
            f"  source-zone {src_zone}",
            f"  source-address {src_addr}",
            f"  destination-zone {dst_zone}",
            f"  destination-address {dst_addr}",
            f"  service {svc}",
            f"  action {action}",
        ]

    # DPtech policy missing source-address -> MANUAL_REVIEW (no implicit "any")
    m = re.match(
        r"security-policy\s+name\s+(\S+)\s+source-zone\s+(\S+)\s+destination-zone\s+(\S+)\s+destination-address\s+(\S+)\s+service\s+(\S+)\s+action\s+(permit|deny)",
        stripped,
        re.IGNORECASE,
    )
    if m:
        return manual_review_comment(
            f"security-policy name={m.group(1)}: missing source-address (DPtech default-any semantics not confirmed)",
            "huawei_usg",
        )

    # DPtech multi-line security-policy block
    if state.get("_in_dptech_secpol"):
        if not indent:
            state["_in_dptech_secpol"] = False
            state.pop("_dptech_secpol", None)
            state["_dptech_secpol_seen_rule"] = False
        else:
            m = re.match(r"rule\s+name\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                state["_dptech_secpol_seen_rule"] = True
                prev = state.get("_dptech_secpol")
                state["_dptech_secpol"] = {"name": m.group(1)}
                if prev and prev.get("name") and prev.get("action"):
                    out = _render_huawei_secpol_rule(prev)
                    state["_dptech_secpol"] = {"name": m.group(1)}
                    return out
                elif prev and prev.get("name"):
                    return manual_review_comment(
                        f"security-policy name={prev['name']} incomplete: missing action", "huawei_usg",
                    )
                return None

            dptech_secpol = state.get("_dptech_secpol") or {}
            name = dptech_secpol.get("name", "UNNAMED")

            m = re.match(r"source-zone\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                dptech_secpol["source_zone"] = m.group(1)
                state["_dptech_secpol"] = dptech_secpol
                return None
            m = re.match(r"destination-zone\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                dptech_secpol["dest_zone"] = m.group(1)
                state["_dptech_secpol"] = dptech_secpol
                return None
            m = re.match(r"source-address\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                dptech_secpol["source_address"] = m.group(1)
                state["_dptech_secpol"] = dptech_secpol
                return None
            m = re.match(r"destination-address\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                dptech_secpol["dest_address"] = m.group(1)
                state["_dptech_secpol"] = dptech_secpol
                return None
            m = re.match(r"service\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                dptech_secpol["service"] = m.group(1)
                state["_dptech_secpol"] = dptech_secpol
                return None
            m = re.match(r"action\s+(permit|deny)", stripped, re.IGNORECASE)
            if m:
                dptech_secpol["action"] = m.group(1)
                state["_dptech_secpol"] = None
                state["_dptech_secpol_seen_rule"] = False
                all_fields = all(k in dptech_secpol for k in ("source_zone", "dest_zone", "source_address", "dest_address", "service", "action"))
                if all_fields:
                    return _render_huawei_secpol_rule(dptech_secpol)
                missing = []
                for f in ("source_zone", "dest_zone", "source_address", "dest_address", "service"):
                    if f not in dptech_secpol:
                        missing.append(f.replace("_", "-"))
                if missing:
                    return manual_review_comment(
                        f"security-policy name={dptech_secpol.get('name','UNNAMED')} incomplete: missing {', '.join(missing)}",
                        "huawei_usg",
                    )
                return _render_huawei_secpol_rule(dptech_secpol)

            return manual_review_comment(
                f"security-policy name={name} unsupported sub: {stripped}", "huawei_usg",
            )

    # DPtech security-policy header (multi-line block start)
    m = re.match(r"security-policy\s+name\s+(\S+)", stripped, re.IGNORECASE)
    if m:
        state["_in_dptech_secpol"] = True
        state["_dptech_secpol"] = {"name": m.group(1)}
        state["_dptech_secpol_seen_rule"] = False
        return None

    # DPtech single-line security-policy -> Huawei USG multi-line (only if all 6 fields present)
    m = re.match(
        r"security-policy\s+name\s+(\S+)\s+"
        r"source-zone\s+(\S+)\s+destination-zone\s+(\S+)\s+"
        r"source-address\s+(\S+)\s+destination-address\s+(\S+)\s+"
        r"service\s+(\S+)\s+action\s+(permit|deny)",
        stripped, re.IGNORECASE,
    )
    if m:
        name, src_zone, dst_zone, src_addr, dst_addr, svc, action = m.groups()
        return _render_huawei_secpol_rule({
            "name": name,
            "source_zone": src_zone,
            "dest_zone": dst_zone,
            "source_address": src_addr,
            "dest_address": dst_addr,
            "service": svc,
            "action": action,
        })

    # DPtech single-line security-policy missing source-address -> MANUAL_REVIEW
    m = re.match(
        r"security-policy\s+name\s+(\S+)\s+"
        r"source-zone\s+(\S+)\s+destination-zone\s+(\S+)\s+"
        r"destination-address\s+(\S+)\s+"
        r"service\s+(\S+)\s+action\s+(permit|deny)",
        stripped, re.IGNORECASE,
    )
    if m:
        return manual_review_comment(
            f"security-policy name={m.group(1)}: missing source-address (DPtech default-any semantics not confirmed)",
            "huawei_usg",
        )

    return manual_review_comment(stripped, "huawei_usg", indent)


def translate_topsec_to_huawei_usg(stripped: str, lower: str, indent: str, from_vendor: str, state: dict) -> Optional[Union[str, list]]:
    if re.search(r"(cipher|password)\s+\S+", lower):
        return "# MANUAL_REVIEW <redacted> (secret/cipher)"
    if (from_vendor or "").lower() == "topsec" and (from_vendor or "").lower() == "huawei_usg":
        return stripped

    if re.search(r"\b(nat|source-nat|destination-nat|ipsec|ike|vpn|tunnel|url-filter|antivirus|av-profile|intrusion|ips|time-range|log\b|session\b|profile\b|application\b|user\b)", lower):
        return manual_review_comment(stripped, "huawei_usg", indent)

    if lower.startswith("zone name "):
        zone_name = re.sub(r"^zone\s+name\s+", "", stripped, flags=re.IGNORECASE)
        return f"security-zone name {zone_name}"

    if lower.startswith("address name "):
        m = re.match(r"address\s+name\s+(\S+)\s+ip\s+(\S+)\s+mask\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            name, ip, mask = m.groups()
            return [f"ip address-set {name} type object", f" address 0 {ip} mask {mask}"]
        return manual_review_comment(stripped, "huawei_usg", indent)

    rv = translate_topsec_service_to_huawei_usg(stripped, lower, indent)
    if rv is not None:
        return rv

    if lower.startswith("policy name "):
        m = re.match(
            r"policy\s+name\s+(\S+)\s+"
            r"source-zone\s+(\S+)\s+"
            r"destination-zone\s+(\S+)\s+"
            r"source-address\s+(\S+)\s+"
            r"destination-address\s+(\S+)\s+"
            r"service\s+(\S+)\s+"
            r"action\s+(permit|deny)",
            stripped, re.IGNORECASE,
        )
        if m:
            name, src_zone, dst_zone, src_addr, dst_addr, svc, action = m.groups()
            return [
                "security-policy",
                f" rule name {name}",
                f"  source-zone {src_zone}",
                f"  destination-zone {dst_zone}",
                f"  source-address {src_addr}",
                f"  destination-address {dst_addr}",
                f"  service {svc}",
                f"  action {action}",
            ]
        if re.search(r"source-zone\s+\S+\s+destination-zone\s+\S+", lower):
            missing = []
            if not re.search(r"source-address\s+\S+", lower):
                missing.append("source-address")
            if not re.search(r"destination-address\s+\S+", lower):
                missing.append("destination-address")
            if not re.search(r"service\s+\S+", lower):
                missing.append("service")
            if not re.search(r"action\s+(permit|deny)", lower):
                missing.append("action")
            if missing:
                m2 = re.match(r"policy\s+name\s+(\S+)", stripped, re.IGNORECASE)
                polname = m2.group(1) if m2 else "UNNAMED"
                return manual_review_comment(
                    f"policy name={polname}: missing {', '.join(missing)} (no implicit defaults)",
                    "huawei_usg", indent,
                )
    return manual_review_comment(stripped, "huawei_usg", indent)


def translate_hillstone_to_topsec(stripped: str, lower: str, indent: str, from_vendor: str, state: dict) -> Optional[Union[str, list]]:
    if re.search(r"(cipher|password)\s+\S+", lower):
        return "# MANUAL_REVIEW <redacted> (secret/cipher)"
    if (from_vendor or "").lower() == "topsec":
        return stripped

    if re.search(r"\b(nat|source-nat|destination-nat|ipsec|ike|vpn|tunnel|url-filter|antivirus|av-profile|intrusion|ips|time-range|log\b|session\b|profile\b|application\b|user\b)", lower):
        return manual_review_comment(stripped, "topsec", indent)

    if re.match(r"zone\s+(\S+)", lower):
        m = re.match(r"zone\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            return f"zone name {m.group(1)}"
        return manual_review_comment(stripped, "topsec", indent)

    if lower.startswith("address "):
        m = re.match(r"address\s+(\S+)\s+(\S+)\s+host", stripped, re.IGNORECASE)
        if m:
            name, ip = m.groups()
            return f"address name {name} ip {ip} mask 255.255.255.255"
        m = re.match(r"address\s+(\S+)\s+(\S+)\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            name, ip, mask = m.groups()
            return f"address name {name} ip {ip} mask {mask}"
        return manual_review_comment(stripped, "topsec", indent)

    rv = translate_hillstone_service_to_topsec(stripped, lower, indent)
    if rv is not None:
        return rv

    m = re.match(
        r"policy\s+(?:name\s+)?(\S+)\s+"
        r"from\s+(\S+)\s+to\s+(\S+)\s+"
        r"(?:src|source)\s+(\S+)\s+"
        r"(?:dst|destination)\s+(\S+)\s+"
        r"service\s+(\S+)\s+"
        r"action\s+(permit|deny)",
        stripped, re.IGNORECASE,
    )
    if m:
        name, src_zone, dst_zone, src_addr, dst_addr, svc, action = m.groups()
        return (
            f"policy name {name} "
            f"source-zone {src_zone} destination-zone {dst_zone} "
            f"source-address {src_addr} destination-address {dst_addr} "
            f"service {svc} action {action}"
        )

    if re.search(r"from\s+\S+\s+to\s+\S+", lower):
        missing = []
        if not re.search(r"(?:src|source)\s+\S+", lower):
            missing.append("source")
        if not re.search(r"(?:dst|destination)\s+\S+", lower):
            missing.append("destination")
        if not re.search(r"service\s+\S+", lower):
            missing.append("service")
        if not re.search(r"action\s+(permit|deny)", lower):
            missing.append("action")
        if missing:
            m2 = re.match(r"policy\s+(?:name\s+)?(\S+)", stripped, re.IGNORECASE)
            polname = m2.group(1) if m2 else "UNNAMED"
            return manual_review_comment(
                f"policy name={polname}: missing {', '.join(missing)} (no implicit defaults)",
                "topsec", indent,
            )

    return manual_review_comment(stripped, "topsec", indent)


def translate_topsec_to_topsec(stripped: str, lower: str, indent: str, from_vendor: str, state: dict) -> Optional[Union[str, list]]:
    if re.search(r"(cipher|password)\s+\S+", lower):
        return "# MANUAL_REVIEW <redacted> (secret/cipher)"

    if re.search(r"\b(nat|source-nat|destination-nat|ipsec|ike|vpn|tunnel|url-filter|antivirus|av-profile|intrusion|ips|time-range|log\b|session\b|profile\b|application\b|user\b)", lower):
        return manual_review_comment(stripped, "topsec", indent)

    if (from_vendor or "").lower() == "topsec":
        return stripped

    return manual_review_comment(stripped, "topsec", indent)


def translate_to_topsec_manual_review(stripped: str, lower: str, indent: str, from_vendor: str) -> str:
    return manual_review_comment(stripped, "topsec", indent)


def translate_topsec_service_to_huawei_usg(stripped: str, lower: str, indent: str) -> Optional[Union[str, List[str]]]:
    if "source-port" in lower:
        return None
    m_port = re.search(r"destination-port\s+([\d,\-]+)", lower)
    if m_port and ("," in m_port.group(1) or "-" in m_port.group(1)):
        return None
    m = re.match(
        r"service\s+(\S+)\s+protocol\s+(tcp|udp|icmp)(?:\s+destination-port\s+(\d+))?",
        stripped,
        re.IGNORECASE,
    )
    if not m:
        return None
    name, protocol, port = m.groups()
    if protocol.lower() == "icmp":
        return [f"ip service-set {name} type object", f" service 0 protocol icmp"]
    if port:
        return [f"ip service-set {name} type object", f" service 0 protocol {protocol.lower()} destination-port {port}"]
    return None


def translate_hillstone_service_to_huawei_usg(stripped: str, lower: str, indent: str) -> Optional[Union[str, List[str]]]:
    if re.search(r"\b\d+-\d+\b", lower) or "," in lower:
        return None
    tokens = lower.split()
    if len(tokens) > 5 or (len(tokens) == 5 and tokens[3] != "dst-port"):
        return None
    m = re.match(r"service\s+(\S+)\s+(tcp|udp|icmp)(?:\s+(?:dst-port\s+)?(\d+))?", stripped, re.IGNORECASE)
    if not m:
        return None
    name, protocol, port = m.groups()
    if protocol.lower() == "icmp":
        return [f"ip service-set {name} type object", f" service 0 protocol icmp"]
    if port:
        return [f"ip service-set {name} type object", f" service 0 protocol {protocol.lower()} destination-port {port}"]
    return None
    return None


def translate_huawei_usg_service_to_hillstone(stripped: str, lower: str, indent: str, state: dict) -> Optional[Union[str, List[str]]]:
    m = re.match(r"ip\s+service-set\s+(\S+)\s+type\s+object", stripped, re.IGNORECASE)
    if m:
        state["_svc_set"] = m.group(1)
        return None
    svc_name = state.get("_svc_set")
    if svc_name:
        if "source-port" in stripped.lower() or re.search(r"destination-port\s+\d+-\d+", stripped) or re.search(r"destination-port\s+\d+,\d+", stripped):
            state.pop("_svc_set", None)
            return manual_review_comment(f"ip service-set {svc_name} sub: {stripped}", "hillstone", indent)
        m = re.match(r"service\s+(\d+)\s+protocol\s+(tcp|udp|icmp)(?:\s+destination-port\s+(\d+))?", stripped, re.IGNORECASE)
        if m:
            state.pop("_svc_set", None)
            svc_index, protocol, port = m.groups()
            port_part = f" {port}" if port else ""
            return f"service {svc_name} {protocol.lower()}{port_part}"
        state.pop("_svc_set", None)
        return manual_review_comment(f"ip service-set {svc_name} sub: {stripped}", "hillstone", indent)
    return None


def translate_hillstone_service_to_topsec(stripped: str, lower: str, indent: str) -> Optional[str]:
    if re.search(r"\b\d+-\d+\b", lower) or "," in lower:
        return None
    tokens = lower.split()
    if len(tokens) > 4:
        return None
    m = re.match(r"service\s+(\S+)\s+(tcp|udp|icmp)(?:\s+(\d+))?", stripped, re.IGNORECASE)
    if not m:
        return None
    name, protocol, port = m.groups()
    if port:
        return f"service {name} protocol {protocol.lower()} destination-port {port}"
    return f"service {name} protocol {protocol.lower()}"


def translate_topsec_service_to_hillstone(stripped: str, lower: str, indent: str) -> Optional[str]:
    if re.search(r"destination-port\s+\d+-\d+", lower) or re.search(r"destination-port\s+\d+,\d+", lower):
        return None
    m = re.match(
        r"service\s+(\S+)\s+protocol\s+(tcp|udp|icmp)(?:\s+destination-port\s+(\d+))?",
        stripped,
        re.IGNORECASE,
    )
    if not m:
        return None
    name, protocol, port = m.groups()
    if port:
        return f"service {name} {protocol.lower()} {port}"
    return f"service {name} {protocol.lower()}"