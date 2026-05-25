# -*- coding: utf-8 -*-
"""SWITCH-domain translation rules for the fallback translator."""

import re
from typing import Optional

from core.fallback.common import (
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

ROUTEMAP_KEYWORDS = ("route-map ", "route-policy ", "ip prefix-list ", "prefix-list ")
STP_CATCH_ALL = ("spanning-tree ", "stp ", "bpduguard", "loopguard", "rootguard")


def translate_to_huawei_switch(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[str]:
    if lower.startswith("hostname "):
        return "sysname " + stripped.split(maxsplit=1)[1]
    if lower.startswith("sysname "):
        return stripped

    # interface range → MANUAL_REVIEW (no direct Huawei equivalent)
    if lower.startswith("interface range"):
        return indent + manual_review_comment(stripped, "huawei", indent)

    m = re.match(r"^vlan\s+(\S.*)", stripped, re.IGNORECASE)
    if m:
        vlan_val = m.group(1)
        if from_vendor in ("huawei", "h3c"):
            return stripped
        vlans = parse_vlan_list(vlan_val)
        if len(vlans) == 1:
            return f"vlan {vlans[0]}"
        return f"vlan batch {format_vlans_huawei_batch(vlans)}"

    m = re.match(r"^interface\s+Vlan(\d+)$", stripped, re.IGNORECASE)
    if m:
        return f"interface Vlanif{m.group(1)}"

    # switchport trunk allowed vlan add → translate with MANUAL_REVIEW
    m = re.match(r"switchport\s+trunk\s+allowed\s+vlan\s+add\s+(.+)", lower)
    if m:
        vlans = normalize_vlan_list(m.group(1))
        return indent + "port trunk allow-pass vlan " + vlans + "\n" + indent + manual_review_comment(
            f"switchport trunk allowed vlan add {m.group(1)}: incremental add semantics, verify full allowed list",
            "huawei", indent,
        )

    # switchport trunk allowed vlan remove → undo allow-pass
    m = re.match(r"switchport\s+trunk\s+allowed\s+vlan\s+remove\s+(.+)", lower)
    if m:
        vlans = normalize_vlan_list(m.group(1))
        return indent + "undo port trunk allow-pass vlan " + vlans

    # switchport trunk allowed vlan all/none → MANUAL_REVIEW
    if re.match(r"switchport\s+trunk\s+allowed\s+vlan\s+(all|none)\s*$", lower):
        return indent + manual_review_comment(stripped, "huawei", indent)

    # switchport trunk native vlan → pvid
    m = re.match(r"switchport\s+trunk\s+native\s+vlan\s+(\S+)", lower)
    if m:
        return indent + "port trunk pvid vlan " + m.group(1)

    if lower.startswith("interface "):
        name = stripped.split(maxsplit=1)[1]
        name = normalize_interface_to_huawei(name)
        return "interface " + name
    if lower.startswith("description "):
        return indent + stripped
    if lower.startswith("ip address "):
        return indent + stripped
    if lower.startswith("port link-type "):
        return indent + stripped  # passthrough for huawei/h3c -> huawei
    if lower.startswith("port default vlan "):
        return indent + stripped  # passthrough for huawei/h3c -> huawei
    if lower.startswith("port trunk ") and from_vendor in ("huawei", "h3c") and not re.match(r"port trunk permit", lower):
        return indent + stripped  # passthrough for huawei/h3c -> huawei
    if re.match(r"port trunk permit vlan", lower) and from_vendor in ("huawei", "h3c"):
        vlan_part = re.sub(r"^port trunk permit vlan\s*", "", lower)
        return indent + "port trunk allow-pass vlan " + vlan_part
    if lower == "no shutdown":
        return indent + "undo shutdown"
    if lower == "no switchport":
        return None
    if lower == "shutdown":
        return indent + "shutdown"
    if lower.startswith("port link-type trunk"):
        return indent + "switchport mode trunk"
    if lower.startswith("port link-type access"):
        return indent + "switchport mode access"
    m = re.match(r"port default vlan\s+(.+)", stripped, re.IGNORECASE)
    if m:
        return indent + "switchport access vlan " + normalize_vlan_list(m.group(1))
    m = re.match(r"port trunk (allow-pass|permit) vlan\s+(.+)", stripped, re.IGNORECASE)
    if m and from_vendor in ("huawei", "h3c", "cisco", "ruijie"):
        return indent + "switchport trunk allowed vlan " + normalize_vlan_list_cisco(m.group(2))
    if lower in ("spanning-tree portfast", "stp edged-port"):
        return indent + "stp edged-port enable"
    if from_vendor in ("h3c", "huawei") and lower.startswith(
        ("port link-type ", "port default vlan ", "port trunk allow-pass vlan ", "stp edged-port enable")
    ):
        return indent + stripped
    # undo port trunk permit vlan → undo port trunk allow-pass vlan (H3C→Huawei)
    m = re.match(r"undo\s+port\s+trunk\s+permit\s+vlan\s+(.+)", lower)
    if m:
        vlans = normalize_vlan_list(m.group(1))
        return indent + "undo port trunk allow-pass vlan " + vlans
    if lower.startswith("undo "):
        return indent + stripped
    if re.match(r"stp\s+(?:instance\s+\d+|mode\s+|priority\s+\d+|bpdu-protection|root-protection|bpduguard)", lower):
        return indent + manual_review_comment(stripped, "huawei", indent)
    if lower.startswith("loopdetect"):
        return indent + manual_review_comment(stripped, "huawei", indent)
    if lower.startswith("mad "):
        return indent + manual_review_comment(stripped, "huawei", indent)
    if lower.startswith("mode lacp"):
        return indent + stripped
    # port trunk pvid → passthrough for huawei target
    if re.match(r"port trunk pvid vlan", lower):
        return indent + stripped
    return None


def translate_switching_to_huawei(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[str]:
    if lower == "switchport trunk encapsulation dot1q":
        return None
    if lower == "switchport mode trunk":
        return indent + "port link-type trunk"
    if lower == "switchport mode access":
        return indent + "port link-type access"
    m = re.match(r"switchport\s+access\s+vlan\s+(.+)", lower)
    if m:
        return indent + "port default vlan " + normalize_vlan_list(m.group(1))
    # switchport trunk allowed vlan — skip add/remove/all/none (handled above)
    m = re.match(r"switchport\s+trunk\s+(?:allowed|allow-pass)\s+vlan\s+(.+)", lower)
    if m and from_vendor in ("cisco", "ruijie"):
        vlan_val = m.group(1)
        if vlan_val.strip().lower() in ("add", "remove", "all", "none") or re.match(r"^(add|remove)\s+", vlan_val.strip().lower()):
            return None
        return indent + "port trunk allow-pass vlan " + normalize_vlan_list(vlan_val)
    m = re.match(r"switchport\s+trunk\s+native\s+vlan\s+(\S+)", lower)
    if m:
        return indent + "native vlan " + m.group(1)
    m = re.match(r"port\s+trunk\s+permit\s+vlan\s+(.+)", stripped, re.IGNORECASE)
    if m and from_vendor in ("cisco", "ruijie"):
        return indent + "port trunk allow-pass vlan " + normalize_vlan_list(m.group(1))
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


def translate_to_cisco_switch(stripped: str, lower: str, indent: str, from_vendor: str, state: dict) -> Optional[str]:
    if lower.startswith("sysname "):
        return "hostname " + stripped.split(maxsplit=1)[1]
    if lower.startswith("hostname "):
        return stripped

    # interface range → MANUAL_REVIEW (no direct Cisco equivalent from non-Cisco sources)
    if lower.startswith("interface range"):
        return manual_review_comment(stripped, "cisco", indent)

    m = re.match(r"vlan\s+batch\s+(.+)", stripped, re.IGNORECASE)
    if m:
        state["unsupported_interface"] = False
        vlans = parse_vlan_list(m.group(1))
        return "vlan " + format_vlans_cisco(vlans)
    m = re.match(r"^vlan\s+(\S.*)", stripped, re.IGNORECASE)
    if m:
        state["unsupported_interface"] = False
        vlans = parse_vlan_list(m.group(1))
        return "vlan " + format_vlans_cisco(vlans)

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
        name = normalize_interface_to_cisco(name)
        if name is None:
            state["unsupported_interface"] = True
            return manual_review_comment(stripped, "cisco", indent)
        state["unsupported_interface"] = False
        return f"interface {name}"
    if state.get("unsupported_interface") and indent:
        return manual_review_comment(stripped, "cisco", indent)
    if lower.startswith("description "):
        return indent + stripped
    if lower.startswith("ip address ") and lower.endswith(" sub"):
        return indent + stripped[:-4] + " secondary"
    if lower.startswith("ip address "):
        return indent + stripped
    if lower == "undo shutdown":
        return indent + "no shutdown"
    if lower == "undo portswitch":
        return indent + "no switchport"
    if lower == "shutdown":
        return indent + "shutdown"
    if lower.startswith("port link-type trunk"):
        return indent + "switchport mode trunk"
    if lower.startswith("port link-type access"):
        return indent + "switchport mode access"
    m = re.match(r"port default vlan\s+(.+)", stripped, re.IGNORECASE)
    if m:
        return indent + "switchport access vlan " + normalize_vlan_list(m.group(1))
    m = re.match(r"port trunk (allow-pass|permit) vlan\s+(.+)", stripped, re.IGNORECASE)
    if m:
        return indent + "switchport trunk allowed vlan " + normalize_vlan_list_cisco(m.group(2))
    # undo port trunk allow-pass vlan → switchport trunk allowed vlan remove
    m = re.match(r"undo\s+port\s+trunk\s+(?:allow-pass|permit)\s+vlan\s+(.+)", lower)
    if m:
        return indent + "switchport trunk allowed vlan remove " + normalize_vlan_list_cisco(m.group(1))
    # port trunk pvid → switchport trunk native vlan
    m = re.match(r"port\s+trunk\s+pvid\s+vlan\s+(\S+)", lower)
    if m:
        return indent + "switchport trunk native vlan " + m.group(1)
    # bare native vlan without trunk context → MANUAL_REVIEW
    if re.match(r"native\s+vlan\s+\S+", lower) and from_vendor != "cisco":
        return indent + manual_review_comment(stripped, "cisco", indent)
    m = re.match(r"(eth-trunk|port link-aggregation group|bridge-aggregation)\s+(\d+)", stripped, re.IGNORECASE)
    if m:
        return indent + f"channel-group {m.group(2)} mode active"
    m = re.match(r"port-group\s+(\d+)", stripped, re.IGNORECASE)
    if m:
        return indent + f"channel-group {m.group(1)} mode active"
    if lower.startswith("stp edged-port"):
        return indent + "spanning-tree portfast"
    # stp bpdu-protection → spanning-tree bpduguard enable
    if re.match(r"stp\s+bpdu-protection", lower):
        return indent + "spanning-tree bpduguard enable"
    # stp root-protection → spanning-tree guard root
    if re.match(r"stp\s+root-protection", lower):
        return indent + "spanning-tree guard root"
    if re.match(r"stp\s+(?:instance\s+\d+|mode\s+\S+|priority\s+\d+|bpduguard)", lower):
        return manual_review_comment(stripped, "cisco", indent)
    if lower.startswith("loopdetect"):
        return manual_review_comment(stripped, "cisco", indent)
    if lower.startswith("mad "):
        return manual_review_comment(stripped, "cisco", indent)
    if lower.startswith("mode lacp"):
        return manual_review_comment(stripped, "cisco", indent)
    if re.match(r"port trunk pvid vlan", lower):
        return manual_review_comment(stripped, "cisco", indent)
    if lower.startswith("undo "):
        return manual_review_comment(stripped, "cisco", indent)
    return None


def translate_to_h3c_switch(stripped: str, lower: str, indent: str, from_vendor: str, state: dict) -> Optional[str]:
    if lower.startswith("hostname "):
        return "sysname " + stripped.split(maxsplit=1)[1]
    if lower.startswith("sysname "):
        return stripped
    # interface range → MANUAL_REVIEW
    if lower.startswith("interface range"):
        return manual_review_comment(stripped, "h3c", indent)
    # switchport trunk allowed vlan add → translate + MANUAL_REVIEW
    m = re.match(r"switchport\s+trunk\s+allowed\s+vlan\s+add\s+(.+)", lower)
    if m:
        vlans = normalize_vlan_list(m.group(1))
        return indent + "port trunk permit vlan " + vlans + "\n" + indent + manual_review_comment(
            f"switchport trunk allowed vlan add {m.group(1)}: incremental add semantics, verify full list",
            "h3c", indent,
        )
    # switchport trunk allowed vlan remove → undo permit
    m = re.match(r"switchport\s+trunk\s+allowed\s+vlan\s+remove\s+(.+)", lower)
    if m:
        vlans = normalize_vlan_list(m.group(1))
        return indent + "undo port trunk permit vlan " + vlans
    # switchport trunk native vlan → pvid
    m = re.match(r"switchport\s+trunk\s+native\s+vlan\s+(\S+)", lower)
    if m:
        return indent + "port trunk pvid vlan " + m.group(1)
    m = re.match(r"^vlan\s+(\S.*)", stripped, re.IGNORECASE)
    if m:
        vlan_val = m.group(1)
        if from_vendor in ("huawei", "h3c"):
            return stripped
        vlans = parse_vlan_list(vlan_val)
        if len(vlans) == 1:
            return f"vlan {vlans[0]}"
        return f"vlan {' to '.join(str(v) for v in vlans)}"
    m = re.match(r"^interface\s+Vlan(\d+)$", stripped, re.IGNORECASE)
    if m:
        return f"interface Vlan-interface{m.group(1)}"
    if lower.startswith("interface "):
        return "interface " + normalize_interface_to_h3c(stripped.split(maxsplit=1)[1])
    if lower == "switchport mode trunk":
        return indent + "port link-type trunk"
    if lower == "switchport mode access":
        return indent + "port link-type access"
    m = re.match(r"switchport\s+trunk\s+allowed\s+vlan\s+(.+)", stripped, re.IGNORECASE)
    if m:
        return indent + "port trunk permit vlan " + normalize_vlan_list(m.group(1))
    m = re.match(r"switchport\s+access\s+vlan\s+(.+)", stripped, re.IGNORECASE)
    if m:
        return indent + "port default vlan " + normalize_vlan_list(m.group(1))
    m = re.match(r"(channel-group|eth-trunk|port-group|bridge-aggregation)\s+(\d+)(?:\s+mode\s+\S+)?", stripped, re.IGNORECASE)
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
    m = re.match(r"^interface\s+Vlanif(\d+)$", stripped, re.IGNORECASE)
    if m:
        return f"interface Vlan-interface{m.group(1)}"
    if lower.startswith("undo "):
        return indent + stripped
    return None


def translate_to_ruijie_switch(stripped: str, lower: str, indent: str, from_vendor: str, state: dict) -> Optional[str]:
    if lower.startswith("sysname "):
        return "hostname " + stripped.split(maxsplit=1)[1]
    if lower.startswith("hostname "):
        return stripped
    # interface range → MANUAL_REVIEW for non-Ruijie source
    if lower.startswith("interface range"):
        if from_vendor in ("ruijie",):
            return indent + stripped
        return manual_review_comment(stripped, "ruijie", indent)
    # switchport trunk allowed vlan add → translate + MANUAL_REVIEW
    m = re.match(r"switchport\s+trunk\s+allowed\s+vlan\s+add\s+(.+)", lower)
    if m:
        vlans = normalize_vlan_list_cisco(m.group(1))
        return indent + "switchport trunk allowed vlan " + vlans + "\n" + indent + manual_review_comment(
            f"switchport trunk allowed vlan add {m.group(1)}: incremental add semantics, verify full list",
            "ruijie", indent,
        )
    m = re.match(r"^vlan\s+batch\s+(.+)", stripped, re.IGNORECASE)
    if m:
        vlans = parse_vlan_list(m.group(1))
        return "vlan " + format_vlans_cisco(vlans)
    m = re.match(r"^vlan\s+(\S.*)", stripped, re.IGNORECASE)
    if m:
        vlans = parse_vlan_list(m.group(1))
        return "vlan " + format_vlans_cisco(vlans)
    m = re.match(r"^interface\s+Vlanif(\d+)$", stripped, re.IGNORECASE)
    if m:
        return f"interface Vlan{m.group(1)}"
    m = re.match(r"^interface\s+Vlan-interface(\d+)$", stripped, re.IGNORECASE)
    if m:
        return f"interface Vlan{m.group(1)}"
    if lower.startswith("interface "):
        name = normalize_interface_to_ruijie(stripped.split(maxsplit=1)[1])
        if name is None:
            state["unsupported_interface"] = True
            return manual_review_comment(stripped, "ruijie", indent)
        state["unsupported_interface"] = False
        return "interface " + name
    if state.get("unsupported_interface") and indent:
        return manual_review_comment(stripped, "ruijie", indent)
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
    if re.match(r"port trunk (allow-pass|permit) vlan\s+(.+)", stripped, re.IGNORECASE):
        vlans = re.match(r"port trunk (?:allow-pass|permit) vlan\s+(.+)", stripped, re.IGNORECASE).group(1)
        return indent + "switchport trunk allowed vlan " + normalize_vlan_list_cisco(vlans)
    if re.match(r"port default vlan\s+(.+)", stripped, re.IGNORECASE):
        vlan = re.match(r"port default vlan\s+(.+)", stripped, re.IGNORECASE).group(1)
        return indent + "switchport access vlan " + normalize_vlan_list_cisco(vlan)
    if lower in ("stp edged-port", "stp edged-port enable"):
        return indent + "spanning-tree portfast"
    if lower.startswith("spanning-tree "):
        if lower in ("spanning-tree portfast",):
            return indent + "spanning-tree portfast"
        return indent + manual_review_comment(stripped, "ruijie", indent)
    if re.match(r"(channel-group|eth-trunk|port-group|bridge-aggregation)\s+(\d+)(?:\s+mode\s+\S+)?", stripped, re.IGNORECASE):
        m = re.match(r"(channel-group|eth-trunk|port-group|bridge-aggregation)\s+(\d+)", stripped, re.IGNORECASE)
        return indent + f"port-group {m.group(2)} mode active"
    if lower.startswith("switchport "):
        return indent + stripped
    if lower == "no switchport":
        return None
    if lower.startswith("undo "):
        if from_vendor in ("huawei", "h3c"):
            return indent + manual_review_comment(stripped, "ruijie", indent)
        return indent + stripped
    return None
