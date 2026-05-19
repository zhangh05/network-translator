from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer


# ── Huawei / H3C ──────────────────────────────────────────────────
_RE_HW_VPN_INSTANCE = re.compile(
    r"^\s*ip\s+vpn-instance\s+(\S+)", re.IGNORECASE,
)
_RE_HW_RD = re.compile(
    r"^\s*route-distinguisher\s+(\S+)", re.IGNORECASE,
)
_RE_HW_VPN_TARGET = re.compile(
    r"^\s*vpn-target\s+(\S+(?:\s+\S+)*?)\s*(import|export|import-extcommunity|export-extcommunity|both)?",
    re.IGNORECASE,
)
_RE_HW_BIND_VPN = re.compile(
    r"^\s*ip\s+binding\s+vpn-instance\s+(\S+)", re.IGNORECASE,
)

# ── Cisco ─────────────────────────────────────────────────────────
_RE_CISCO_VRF_DEF = re.compile(
    r"^\s*vrf\s+definition\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_RD = re.compile(
    r"^\s*rd\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_ROUTE_TARGET = re.compile(
    r"^\s*route-target\s+(import|export|both)\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_VRF_FORWARDING = re.compile(
    r"^\s*vrf\s+forwarding\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_ADDR_FAMILY = re.compile(
    r"^\s*address-family\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_EXIT_ADDR_FAMILY = re.compile(
    r"^\s*exit-address-family", re.IGNORECASE,
)

_RE_INTERFACE = re.compile(
    r"^\s*interface\s+(\S+)", re.IGNORECASE,
)

_HW_VENDORS = {"huawei", "h3c"}
_CISCO_VENDORS = {"cisco"}


def _is_vrf_line(l: str) -> bool:
    ll = l.lower().strip()
    return (
        "vpn-instance" in ll or "vrf definition" in ll
        or "route-distinguisher" in ll or "vpn-target" in ll
        or "route-target" in ll or "vrf forwarding" in ll
    )


class VrfAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "vrf"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        lines = config_text.splitlines()
        vendor_lower = vendor.lower()
        is_hw = vendor_lower in _HW_VENDORS
        is_cisco = vendor_lower in _CISCO_VENDORS

        if not is_hw and not is_cisco:
            return FeatureAnalysis(
                feature="vrf", status="skipped", risk_level="info",
                notes=[f"Vendor {vendor} not supported"],
            )

        any_vrf = any(_is_vrf_line(l) for l in lines)
        if not any_vrf:
            return FeatureAnalysis(
                feature="vrf", status="skipped", risk_level="info",
                notes=["未发现 VRF 配置"],
            )

        vrfs: Dict[str, Dict] = {}
        interface_bindings: List[tuple] = []
        refs: Dict[str, List[str]] = {"interface": []}
        missing: List[str] = []

        if is_hw:
            self._parse_hw(lines, vrfs, interface_bindings, refs, missing)
        if is_cisco:
            self._parse_cisco(lines, vrfs, interface_bindings, refs, missing)

        self._cross_ref(vrfs, interface_bindings, missing, refs)

        rules = []
        for vname, vdata in vrfs.items():
            rules.append({
                "vrf_name": vname,
                "rd": vdata.get("rd", ""),
                "route_targets": vdata.get("route_targets", {}),
                "bound_interfaces": vdata.get("bound_interfaces", []),
                "source_lines": [],
            })

        if not rules:
            if missing:
                has_fatal = any("fatal" in m for m in missing)
                risk = "fatal" if has_fatal else "warning"
                return FeatureAnalysis(
                    feature="vrf", status="analyzed",
                    risk_level=risk,
                    manual_review_required=True,
                    missing_context=missing,
                    references=refs,
                    notes=["VRF 引用错误但无已定义 VRF"],
                )
            return FeatureAnalysis(
                feature="vrf", status="skipped", risk_level="info",
                notes=["包含 VRF 关键词但未识别到完整定义"],
            )

        has_fatal = any("fatal" in m for m in missing)
        risk = "info"
        if missing:
            risk = "warning"
        if has_fatal:
            risk = "fatal"

        return FeatureAnalysis(
            feature="vrf",
            status="analyzed",
            risk_level=risk,
            manual_review_required=risk in ("warning", "fatal"),
            rules=rules,
            references=refs,
            missing_context=missing,
            source_lines=[],
            notes=[],
        )

    def _parse_hw(self, lines, vrfs, interface_bindings, refs, missing):
        current_vrf: Optional[str] = None
        vrf_indent = 0
        current_interface: Optional[str] = None
        in_addr_family = False

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue
            indent = len(raw) - len(raw.lstrip())

            m = _RE_HW_VPN_INSTANCE.match(stripped)
            if m:
                current_vrf = m.group(1)
                vrf_indent = indent
                vrfs[current_vrf] = {"rd": "", "route_targets": {"import": [], "export": []}, "bound_interfaces": []}
                in_addr_family = False
                continue

            m = _RE_INTERFACE.match(stripped)
            if m:
                current_interface = m.group(1)
                current_vrf = None
                in_addr_family = False
                refs["interface"].append(current_interface)
                continue

            # ── Interface binding ──
            mm = _RE_HW_BIND_VPN.match(stripped)
            if mm and current_interface:
                vname = mm.group(1)
                interface_bindings.append((current_interface, vname))
                continue

            # ── Inside vpn-instance ──
            if current_vrf and indent > vrf_indent:
                mm = _RE_HW_RD.match(stripped)
                if mm:
                    vrfs[current_vrf]["rd"] = mm.group(1)
                    continue
                mm = _RE_HW_VPN_TARGET.match(stripped)
                if mm:
                    target = mm.group(1)
                    direction = (mm.group(2) or "both").lower()
                    if direction in ("import", "import-extcommunity"):
                        vrfs[current_vrf]["route_targets"]["import"].append(target)
                    elif direction in ("export", "export-extcommunity"):
                        vrfs[current_vrf]["route_targets"]["export"].append(target)
                    else:
                        vrfs[current_vrf]["route_targets"]["import"].append(target)
                        vrfs[current_vrf]["route_targets"]["export"].append(target)
                    continue
                # Not a recognized sub-command — stay in vrf context
                continue

    def _parse_cisco(self, lines, vrfs, interface_bindings, refs, missing):
        current_vrf: Optional[str] = None
        vrf_indent = 0
        current_interface: Optional[str] = None
        in_addr_family = False

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue
            indent = len(raw) - len(raw.lstrip())

            m = _RE_CISCO_VRF_DEF.match(stripped)
            if m:
                current_vrf = m.group(1)
                vrf_indent = indent
                vrfs[current_vrf] = {"rd": "", "route_targets": {"import": [], "export": []}, "bound_interfaces": []}
                in_addr_family = False
                continue

            m = _RE_INTERFACE.match(stripped)
            if m:
                current_interface = m.group(1)
                current_vrf = None
                in_addr_family = False
                refs["interface"].append(current_interface)
                continue

            # ── Interface binding ──
            mm = _RE_CISCO_VRF_FORWARDING.match(stripped)
            if mm and current_interface:
                vname = mm.group(1)
                interface_bindings.append((current_interface, vname))
                continue

            # ── Inside vrf definition ──
            if current_vrf and indent > vrf_indent:
                mm = _RE_CISCO_ADDR_FAMILY.match(stripped)
                if mm:
                    in_addr_family = True
                    continue
                mm = _RE_CISCO_EXIT_ADDR_FAMILY.match(stripped)
                if mm:
                    in_addr_family = False
                    continue
                mm = _RE_CISCO_RD.match(stripped)
                if mm:
                    vrfs[current_vrf]["rd"] = mm.group(1)
                    continue
                mm = _RE_CISCO_ROUTE_TARGET.match(stripped)
                if mm:
                    direction = mm.group(1).lower()
                    target = mm.group(2)
                    if direction == "both":
                        vrfs[current_vrf]["route_targets"]["import"].append(target)
                        vrfs[current_vrf]["route_targets"]["export"].append(target)
                    elif direction == "import":
                        vrfs[current_vrf]["route_targets"]["import"].append(target)
                    elif direction == "export":
                        vrfs[current_vrf]["route_targets"]["export"].append(target)
                    continue
                continue

    @staticmethod
    def _cross_ref(vrfs, interface_bindings, missing, refs):
        defined = set(vrfs.keys())
        bound_names = set()

        for iface, vname in interface_bindings:
            bound_names.add(vname)
            if vname not in defined:
                missing.append(
                    f"接口 {iface} 引用了未定义的 VRF {vname}——fatal"
                )
            else:
                if vname not in vrfs.get(vname, {}).get("bound_interfaces", []):
                    vrfs[vname].setdefault("bound_interfaces", []).append(iface)

        for vname, vdata in vrfs.items():
            if not vdata.get("rd"):
                missing.append(f"VRF {vname} 缺少 route-distinguisher——warning")
            if not vdata.get("route_targets", {}).get("import") and not vdata.get("route_targets", {}).get("export"):
                missing.append(f"VRF {vname} 没有 route-target——warning")
            if vname not in bound_names:
                missing.append(f"VRF {vname} 已定义但未绑定任何接口——warning")
