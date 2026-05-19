# -*- coding: utf-8 -*-
"""Domain / platform type definitions and detection."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional


# ── Domain ──────────────────────────────────────────────────────────────────

DOMAIN_VALUES = {
    "routing": "路由",
    "switching": "交换",
    "firewall": "防火墙",
    "unknown": "未知",
}


def normalize_domain(s: str) -> str:
    if not s or s in ("auto", "unknown"):
        return "unknown"
    return s.lower()


def validate_domain(s: str) -> bool:
    return s in DOMAIN_VALUES or s == "auto"


# ── Vendor → Domain mapping ─────────────────────────────────────────────────

DOMAIN_VENDORS: Dict[str, List[str]] = {
    "routing": ["huawei", "h3c", "cisco", "ruijie"],
    "switching": ["huawei", "h3c", "cisco", "ruijie"],
    "firewall": ["huawei", "h3c", "cisco", "hillstone", "topsec", "dbappsecurity", "dptech"],
}

ALL_VENDORS: List[str] = sorted({
    v for vendors in DOMAIN_VENDORS.values() for v in vendors
})

ALL_DOMAINS: List[str] = list(DOMAIN_VENDORS.keys())


# ── Platform ────────────────────────────────────────────────────────────────

VENDOR_PLATFORMS: Dict[str, List[str]] = {
    "huawei":     ["vrp", "usg", "unknown"],
    "h3c":        ["comware", "secpath", "unknown"],
    "cisco":      ["ios", "ios-xe", "nx-os", "asa", "ftd", "unknown"],
    "ruijie":     ["rg-os", "unknown"],
    "hillstone":  ["stoneos", "unknown"],
    "topsec":     ["topsec-os", "unknown"],
    "dbappsecurity": ["unknown"],
    "dptech":     ["unknown"],
}


def validate_platform(platform: str, vendor: str) -> bool:
    if not platform or platform in ("auto", "unknown"):
        return True
    valid = VENDOR_PLATFORMS.get(vendor.lower(), [])
    return platform.lower() in valid


# ── Domain detection ────────────────────────────────────────────────────────

def detect_domain(vendor: str, config_text: str = "") -> str:
    vendor_lower = vendor.lower()

    # If vendor uniquely identifies domain
    if vendor_lower in ("hillstone", "topsec", "dbappsecurity", "dptech"):
        return "firewall"

    # Check config for strong domain signals
    text = config_text.lower()

    # Firewall signals
    if re.search(r'security-zone|security-policy|security.zone|firewall\s+zone', text):
        return "firewall"

    # Switching signals
    if re.search(r'(vlan\s+\d+|interface\s+vlanif|switchport|port\s+link-type|'
                 r'spanning-tree|stp\s+mode|interface\s+Port-Channel'
                 r'|interface\s+range|port\s+trunk)', text):
        return "switching"

    # Routing signals
    if re.search(r'(router\s+(ospf|bgp|isis|rip)|'
                 r'ip\s+route|ip\s+route-static|'
                 r'route-map|prefix-list|'
                 r'neighbor\s+\d+\.\d+\.\d+\.\d+|'
                 r'peer\s+\d+\.\d+\.\d+\.\d+)|'
                 r'(interface\s+GigabitEthernet|interface\s+Ethernet)', text):
        return "routing"

    return "routing"


# ── Platform detection ──────────────────────────────────────────────────────

def detect_platform(vendor: str, domain: str, config_text: str = "") -> str:
    vendor_lower = vendor.lower()
    text = config_text.lower()

    if vendor_lower == "cisco":
        if re.search(r'security-level|access-group\s+|object\s+network|object-group', text):
            return "asa"
        if re.search(r'switchport\s+|vlan\s+\d+|interface\s+vlan', text):
            return "nx-os"
        return "ios"

    if vendor_lower == "huawei":
        if re.search(r'security-zone|security-policy|zone\s+|nat-policy', text):
            return "usg"
        return "vrp"

    if vendor_lower == "h3c":
        if re.search(r'secpath|security-zone|security-policy', text):
            return "secpath"
        return "comware"

    if vendor_lower == "ruijie":
        if re.search(r'switchport|vlan\s+', text):
            return "rg-os"
        return "rg-os"

    return "unknown"


# ── Cache helpers ───────────────────────────────────────────────────────────

def domains_for_vendor(vendor: str) -> List[str]:
    """Return all domains a vendor can participate in."""
    v = vendor.lower()
    return [d for d, vendors in DOMAIN_VENDORS.items() if v in vendors]


def platforms_for_vendor(vendor: str) -> List[str]:
    return VENDOR_PLATFORMS.get(vendor.lower(), ["unknown"])


# ── Feature Registry ─────────────────────────────────────────────────────────

_REGISTRY_CACHE: Optional[Dict] = None


def _load_registry() -> dict:
    global _REGISTRY_CACHE
    if _REGISTRY_CACHE is not None:
        return _REGISTRY_CACHE
    p = Path(__file__).parent.parent / "knowledge_data" / "features" / "registry.yaml"
    if not p.exists():
        _REGISTRY_CACHE = {}
        return _REGISTRY_CACHE
    try:
        import yaml
        with open(p) as f:
            raw = yaml.safe_load(f) or {}
        _REGISTRY_CACHE = raw.get("features", {})
    except Exception:
        _REGISTRY_CACHE = {}
    return _REGISTRY_CACHE


def get_all_features() -> Dict[str, dict]:
    return dict(_load_registry())


def get_feature_domains(feature: str) -> List[str]:
    entry = _load_registry().get(feature)
    if not entry:
        return []
    return entry.get("domains", [])


def get_features_for_domain(domain: str) -> List[str]:
    return [
        name for name, meta in _load_registry().items()
        if domain in meta.get("domains", [])
    ]


def get_feature_priority(feature: str) -> str:
    entry = _load_registry().get(feature)
    return (entry or {}).get("priority", "p3")


def get_feature_risk(feature: str) -> str:
    entry = _load_registry().get(feature)
    return (entry or {}).get("risk", "medium")
