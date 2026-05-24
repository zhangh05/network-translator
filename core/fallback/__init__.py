# -*- coding: utf-8 -*-
"""core.fallback: Deterministic multi-vendor fallback rule modules.

Modules:
    common  — shared helpers: MANUAL_REVIEW, VLAN parse/format, interface normalization
    switch_rules  — SWITCH domain: hostname/VLAN/interface/trunk/access/LAG/STP
    router_rules  — ROUTER domain: static route/OSPF/BGP/VRF
    firewall_rules — FIREWALL domain: USG/Hillstone/Topsec/DPtech
"""

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

__all__ = [
    "manual_review_comment",
    "parse_vlan_list",
    "format_vlans_cisco",
    "format_vlans_huawei_batch",
    "normalize_vlan_list",
    "normalize_vlan_list_cisco",
    "normalize_interface_to_cisco",
    "normalize_interface_to_huawei",
    "normalize_interface_to_h3c",
    "normalize_interface_to_ruijie",
]