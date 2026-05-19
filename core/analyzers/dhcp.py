from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer


# ── Huawei / H3C ──────────────────────────────────────────────────
_RE_HW_DHCP_ENABLE = re.compile(
    r"^\s*dhcp\s+enable", re.IGNORECASE,
)
_RE_HW_IP_POOL = re.compile(
    r"^\s*ip\s+pool\s+(\S+)", re.IGNORECASE,
)
_RE_HW_NETWORK = re.compile(
    r"^\s*network\s+(\S+)\s+(?:mask\s+)?(\S+)?", re.IGNORECASE,
)
_RE_HW_GATEWAY = re.compile(
    r"^\s*gateway-list\s+(.+)", re.IGNORECASE,
)
_RE_HW_DNS = re.compile(
    r"^\s*dns-list\s+(.+)", re.IGNORECASE,
)
_RE_HW_EXCLUDED = re.compile(
    r"^\s*excluded-ip-address\s+(.+)", re.IGNORECASE,
)
_RE_HW_LEASE = re.compile(
    r"^\s*lease\s+day\s+(\S+)|^\s*lease\s+(\S+)", re.IGNORECASE,
)
_RE_HW_OPTION = re.compile(
    r"^\s*option\s+(\S+)", re.IGNORECASE,
)
_RE_HW_IF_DHCP = re.compile(
    r"^\s*dhcp\s+select\s+(global|interface)", re.IGNORECASE,
)

# ── Cisco IOS ─────────────────────────────────────────────────────
_RE_CISCO_SERVICE_DHCP = re.compile(
    r"^\s*service\s+dhcp", re.IGNORECASE,
)
_RE_CISCO_DHCP_POOL = re.compile(
    r"^\s*ip\s+dhcp\s+pool\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_NETWORK = re.compile(
    r"^\s*network\s+(\S+)\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_DEFAULT_ROUTER = re.compile(
    r"^\s*default-router\s+(.+)", re.IGNORECASE,
)
_RE_CISCO_DNS = re.compile(
    r"^\s*dns-server\s+(.+)", re.IGNORECASE,
)
_RE_CISCO_EXCLUDED = re.compile(
    r"^\s*ip\s+dhcp\s+excluded-address\s+(.+)", re.IGNORECASE,
)
_RE_CISCO_LEASE = re.compile(
    r"^\s*lease\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_OPTION = re.compile(
    r"^\s*option\s+(\S+)", re.IGNORECASE,
)

# ── Generic ───────────────────────────────────────────────────────
_RE_INTERFACE = re.compile(
    r"^\s*interface\s+(\S+)", re.IGNORECASE,
)

_HW_VENDORS = {"huawei", "h3c"}
_CISCO_VENDORS = {"cisco"}


def _is_dhcp_line(l: str) -> bool:
    ll = l.lower().strip()
    return (
        "dhcp" in ll or "ip pool" in ll or "ip dhcp" in ll
        or "default-router" in ll or "dns-server" in ll
        or "gateway-list" in ll or "dns-list" in ll
        or "excluded" in ll
    )


def _split_addrs(v: str) -> List[str]:
    parts = v.replace(",", " ").split()
    result = []
    for p in parts:
        p = p.strip()
        if p and p not in result:
            result.append(p)
    return result


class DhcpAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "dhcp"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        lines = config_text.splitlines()
        vendor_lower = vendor.lower()
        is_hw = vendor_lower in _HW_VENDORS
        is_cisco = vendor_lower in _CISCO_VENDORS

        if not is_hw and not is_cisco:
            return FeatureAnalysis(
                feature="dhcp", status="skipped", risk_level="info",
                notes=[f"Vendor {vendor} not supported"],
            )

        any_dhcp = any(_is_dhcp_line(l) for l in lines)
        if not any_dhcp:
            return FeatureAnalysis(
                feature="dhcp", status="skipped", risk_level="info",
                notes=["未发现 DHCP 配置"],
            )

        pools: Dict[str, Dict] = {}
        excluded: List[str] = []
        dhcp_enabled = False
        refs: Dict[str, List[str]] = {"interface": []}
        missing: List[str] = []
        source_lines: List[str] = []

        if is_hw:
            self._parse_hw(lines, pools, excluded, dhcp_enabled, refs, missing)
        if is_cisco:
            self._parse_cisco(lines, pools, excluded, dhcp_enabled, refs, missing)

        if not pools:
            # Still report global dhcp state
            if dhcp_enabled:
                return FeatureAnalysis(
                    feature="dhcp", status="analyzed", risk_level="info",
                    rules=[{"pool_name": "(global)", "note": "DHCP global enabled, no pools defined"}],
                    references=refs, missing_context=missing,
                )
            return FeatureAnalysis(
                feature="dhcp", status="analyzed", risk_level="info",
                rules=[{"pool_name": "(none)", "note": "DHCP disabled or no pool found"}],
                references=refs, missing_context=missing,
            )

        rules = []
        for pname, pdata in pools.items():
            rules.append({
                "pool_name": pname,
                "network": pdata.get("network", ""),
                "gateway": pdata.get("gateway", []),
                "dns": pdata.get("dns", []),
                "excluded": pdata.get("excluded", []),
                "lease": pdata.get("lease", ""),
                "options": pdata.get("options", []),
                "interface_binding": pdata.get("interface_binding", []),
                "source_lines": [],
            })
            if not pdata.get("network"):
                missing.append(f"DHCP pool {pname} 缺少 network——fatal")
            if is_cisco and not pdata.get("gateway"):
                missing.append(f"DHCP pool {pname} 缺少 default-router——warning")
            if not pdata.get("lease"):
                missing.append(f"DHCP pool {pname} 缺少 lease——warning")
            if not pdata.get("dns"):
                missing.append(f"DHCP pool {pname} 缺少 dns——warning")

        has_fatal = any("fatal" in m for m in missing)
        risk = "info"
        if missing:
            risk = "warning"
        if has_fatal:
            risk = "fatal"

        return FeatureAnalysis(
            feature="dhcp",
            status="analyzed",
            risk_level=risk,
            manual_review_required=risk in ("warning", "fatal"),
            rules=rules,
            references=refs,
            missing_context=missing,
            source_lines=source_lines,
            notes=[],
        )

    def _parse_hw(self, lines, pools, excluded, dhcp_enabled, refs, missing):
        current_pool: Optional[str] = None
        pool_indent = 0
        current_interface: Optional[str] = None

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue
            indent = len(raw) - len(raw.lstrip())

            m = _RE_HW_DHCP_ENABLE.match(stripped)
            if m:
                dhcp_enabled = True
                continue

            m = _RE_HW_IP_POOL.match(stripped)
            if m:
                current_pool = m.group(1)
                pool_indent = indent
                pools[current_pool] = {
                    "network": "", "gateway": [], "dns": [],
                    "excluded": [], "lease": "", "options": [],
                    "interface_binding": [],
                }
                continue

            m = _RE_INTERFACE.match(stripped)
            if m:
                current_pool = None
                current_interface = m.group(1)
                refs["interface"].append(current_interface)
                continue

            m = _RE_HW_EXCLUDED.match(stripped)
            if m:
                excluded.append(m.group(1))
                continue

            # ── Inside pool ──
            if current_pool and indent > pool_indent:
                mm = _RE_HW_NETWORK.match(stripped)
                if mm:
                    net = mm.group(1)
                    mask = mm.group(2) or ""
                    pools[current_pool]["network"] = f"{net}/{mask}" if mask else net
                    continue
                mm = _RE_HW_GATEWAY.match(stripped)
                if mm:
                    pools[current_pool]["gateway"] = _split_addrs(mm.group(1))
                    continue
                mm = _RE_HW_DNS.match(stripped)
                if mm:
                    pools[current_pool]["dns"] = _split_addrs(mm.group(1))
                    continue
                mm = _RE_HW_LEASE.match(stripped)
                if mm:
                    pools[current_pool]["lease"] = mm.group(1) or mm.group(2) or ""
                    continue
                mm = _RE_HW_OPTION.match(stripped)
                if mm:
                    pools[current_pool]["options"].append(mm.group(1))
                    continue
                continue

            # ── Interface binding ──
            mm = _RE_HW_IF_DHCP.match(stripped)
            if mm and current_interface:
                mode = mm.group(1)
                if mode == "global":
                    # find pool for this interface
                    pools.setdefault(f"(on {current_interface})", {
                        "network": "?", "gateway": [], "dns": [],
                        "excluded": [], "lease": "", "options": [],
                        "interface_binding": [f"{current_interface} (global)"],
                    })
                elif mode == "interface":
                    pools.setdefault(f"(relay on {current_interface})", {
                        "network": "?", "gateway": [], "dns": [],
                        "excluded": [], "lease": "", "options": [],
                        "interface_binding": [f"{current_interface} (relay)"],
                    })
                continue

        # Attach global excluded to pools
        if excluded:
            for pname in pools:
                pools[pname].setdefault("excluded", []).extend(excluded)

    def _parse_cisco(self, lines, pools, excluded, dhcp_enabled, refs, missing):
        current_pool: Optional[str] = None
        pool_indent = 0
        current_interface: Optional[str] = None

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue
            indent = len(raw) - len(raw.lstrip())

            m = _RE_CISCO_SERVICE_DHCP.match(stripped)
            if m:
                dhcp_enabled = True
                continue

            m = _RE_CISCO_DHCP_POOL.match(stripped)
            if m:
                current_pool = m.group(1)
                pool_indent = indent
                pools[current_pool] = {
                    "network": "", "gateway": [], "dns": [],
                    "excluded": [], "lease": "", "options": [],
                    "interface_binding": [],
                }
                continue

            m = _RE_INTERFACE.match(stripped)
            if m:
                current_interface = m.group(1)
                refs["interface"].append(current_interface)
                continue

            m = _RE_CISCO_EXCLUDED.match(stripped)
            if m:
                excluded.append(m.group(1))
                continue

            # ── Inside pool ──
            if current_pool and indent > pool_indent:
                mm = _RE_CISCO_NETWORK.match(stripped)
                if mm:
                    pools[current_pool]["network"] = f"{mm.group(1)}/{mm.group(2)}"
                    continue
                mm = _RE_CISCO_DEFAULT_ROUTER.match(stripped)
                if mm:
                    pools[current_pool]["gateway"] = _split_addrs(mm.group(1))
                    continue
                mm = _RE_CISCO_DNS.match(stripped)
                if mm:
                    pools[current_pool]["dns"] = _split_addrs(mm.group(1))
                    continue
                mm = _RE_CISCO_LEASE.match(stripped)
                if mm:
                    pools[current_pool]["lease"] = mm.group(1)
                    continue
                mm = _RE_CISCO_OPTION.match(stripped)
                if mm:
                    pools[current_pool]["options"].append(mm.group(1))
                    continue
                continue

        if excluded:
            for pname in pools:
                pools[pname].setdefault("excluded", []).extend(excluded)
