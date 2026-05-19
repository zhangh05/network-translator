from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer


# ── Huawei / H3C VRRP ────────────────────────────────────────────
_RE_HW_VRRP_VRID = re.compile(
    r"^\s*vrrp\s+vrid\s+(\S+)", re.IGNORECASE,
)
_RE_HW_VRRP_VIP = re.compile(
    r"^\s*vrrp\s+vrid\s+\S+\s+virtual-ip\s+(\S+)", re.IGNORECASE,
)
_RE_HW_VRRP_PRI = re.compile(
    r"^\s*vrrp\s+vrid\s+\S+\s+priority\s+(\S+)", re.IGNORECASE,
)
_RE_HW_VRRP_PREEMPT = re.compile(
    r"^\s*vrrp\s+vrid\s+\S+\s+preempt", re.IGNORECASE,
)
_RE_HW_VRRP_TRACK_IF = re.compile(
    r"^\s*vrrp\s+vrid\s+\S+\s+track\s+interface\s+(\S+)", re.IGNORECASE,
)
_RE_HW_VRRP_TRACK_BFD = re.compile(
    r"^\s*vrrp\s+vrid\s+\S+\s+track\s+bfd\s+(\S+)", re.IGNORECASE,
)

# ── Cisco HSRP ────────────────────────────────────────────────────
_RE_CISCO_STANDBY_IP = re.compile(
    r"^\s*standby\s+(\S+)\s+ip\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_STANDBY_PRI = re.compile(
    r"^\s*standby\s+(\S+)\s+priority\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_STANDBY_PREEMPT = re.compile(
    r"^\s*standby\s+(\S+)\s+preempt", re.IGNORECASE,
)
_RE_CISCO_STANDBY_TRACK = re.compile(
    r"^\s*standby\s+(\S+)\s+track\s+(\S+)", re.IGNORECASE,
)

# ── Generic interface ─────────────────────────────────────────────
_RE_INTERFACE = re.compile(
    r"^\s*interface\s+(\S+)", re.IGNORECASE,
)

_HW_VENDORS = {"huawei", "h3c"}
_CISCO_VENDORS = {"cisco"}


def _is_vrrp_line(l: str) -> bool:
    ll = l.lower().strip()
    return ll.startswith("vrrp") or ll.startswith("standby")


class VrrpAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "vrrp"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        lines = config_text.splitlines()
        vendor_lower = vendor.lower()
        is_hw = vendor_lower in _HW_VENDORS
        is_cisco = vendor_lower in _CISCO_VENDORS

        if not is_hw and not is_cisco:
            return FeatureAnalysis(
                feature="vrrp", status="skipped", risk_level="info",
                notes=[f"Vendor {vendor} not supported"],
            )

        any_vrrp = any(_is_vrrp_line(l) for l in lines)
        if not any_vrrp:
            return FeatureAnalysis(
                feature="vrrp", status="skipped", risk_level="info",
                notes=["未发现 VRRP/HSRP 配置"],
            )

        rules: List[Dict] = []
        missing: List[str] = []
        refs: Dict[str, List[str]] = {"interface": []}

        current_interface: Optional[str] = None
        groups: Dict[str, Dict] = {}

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            m = _RE_INTERFACE.match(stripped)
            if m:
                current_interface = m.group(1)
                refs["interface"].append(current_interface)
                continue

            if not current_interface:
                continue

            if is_hw:
                self._parse_hw_line(stripped, current_interface, groups, missing, refs)
            elif is_cisco:
                self._parse_cisco_line(stripped, current_interface, groups, missing, refs)

        if not groups:
            return FeatureAnalysis(
                feature="vrrp", status="skipped", risk_level="info",
                notes=["包含 VRRP 关键词但未识别到完整组配置"],
            )

        for gid, gdata in groups.items():
            rules.append({
                "interface": gdata.get("interface", ""),
                "group_id": gid,
                "virtual_ip": gdata.get("virtual_ip", ""),
                "priority": gdata.get("priority", ""),
                "preempt": gdata.get("preempt", False),
                "track": gdata.get("track", []),
                "source_lines": [],
            })

            if not gdata.get("virtual_ip"):
                missing.append(f"VRRP group {gid} 缺少 virtual-ip——fatal")
            if not gdata.get("interface"):
                missing.append(f"VRRP group {gid} 缺少 interface 上下文——fatal")

        has_fatal = any("fatal" in m for m in missing)
        risk = "info"
        if missing:
            risk = "warning"
        if has_fatal:
            risk = "fatal"

        return FeatureAnalysis(
            feature="vrrp",
            status="analyzed",
            risk_level=risk,
            manual_review_required=risk in ("warning", "fatal"),
            rules=rules,
            references=refs,
            missing_context=missing,
            source_lines=[],
            notes=[],
        )

    @staticmethod
    def _parse_hw_line(stripped, interface, groups, missing, refs):
        m = _RE_HW_VRRP_VIP.match(stripped)
        if m:
            gid = m.group(0).split()[2]
            vip = m.group(1)
            groups.setdefault(gid, {"interface": interface, "track": []})
            groups[gid]["interface"] = interface
            groups[gid]["virtual_ip"] = vip
            return

        m = _RE_HW_VRRP_PRI.match(stripped)
        if m:
            gid = m.group(0).split()[2]
            pri = m.group(1)
            groups.setdefault(gid, {"interface": interface, "track": []})
            groups[gid]["priority"] = pri
            return

        m = _RE_HW_VRRP_PREEMPT.match(stripped)
        if m:
            gid = m.group(0).split()[2]
            groups.setdefault(gid, {"interface": interface, "track": []})
            groups[gid]["preempt"] = True
            return

        m = _RE_HW_VRRP_TRACK_IF.match(stripped)
        if m:
            gid = m.group(0).split()[2]
            tracked = m.group(1)
            groups.setdefault(gid, {"interface": interface, "track": []})
            groups[gid]["track"].append(tracked)
            refs.setdefault("track_interface", []).append(tracked)
            return

        m = _RE_HW_VRRP_TRACK_BFD.match(stripped)
        if m:
            gid = m.group(0).split()[2]
            tracked = m.group(1)
            groups.setdefault(gid, {"interface": interface, "track": []})
            groups[gid]["track"].append(f"bfd:{tracked}")
            refs.setdefault("track_bfd", []).append(tracked)
            return

    @staticmethod
    def _parse_cisco_line(stripped, interface, groups, missing, refs):
        m = _RE_CISCO_STANDBY_IP.match(stripped)
        if m:
            gid = m.group(1)
            vip = m.group(2)
            groups.setdefault(gid, {"interface": interface, "track": []})
            groups[gid]["interface"] = interface
            groups[gid]["virtual_ip"] = vip
            return

        m = _RE_CISCO_STANDBY_PRI.match(stripped)
        if m:
            gid = m.group(1)
            pri = m.group(2)
            groups.setdefault(gid, {"interface": interface, "track": []})
            groups[gid]["priority"] = pri
            return

        m = _RE_CISCO_STANDBY_PREEMPT.match(stripped)
        if m:
            gid = m.group(1)
            groups.setdefault(gid, {"interface": interface, "track": []})
            groups[gid]["preempt"] = True
            return

        m = _RE_CISCO_STANDBY_TRACK.match(stripped)
        if m:
            gid = m.group(1)
            tracked = m.group(2)
            groups.setdefault(gid, {"interface": interface, "track": []})
            groups[gid]["track"].append(tracked)
            refs.setdefault("track_interface", []).append(tracked)
            return
