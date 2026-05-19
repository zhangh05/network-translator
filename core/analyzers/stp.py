from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer


# ── Huawei ────────────────────────────────────────────────────────
_RE_HW_STP_MODE = re.compile(
    r"^\s*stp\s+mode\s+(\S+)", re.IGNORECASE,
)
_RE_HW_REGION = re.compile(
    r"^\s*stp\s+region-configuration", re.IGNORECASE,
)
_RE_HW_INSTANCE_VLAN = re.compile(
    r"^\s*instance\s+(\S+)\s+vlan\s+(.+)", re.IGNORECASE,
)
_RE_HW_ACTIVE = re.compile(
    r"^\s*active\s+region-configuration", re.IGNORECASE,
)
_RE_HW_STP_INSTANCE_ROOT = re.compile(
    r"^\s*stp\s+instance\s+(\S+)\s+root\s+(primary|secondary)", re.IGNORECASE,
)
_RE_HW_STP_INSTANCE_PRI = re.compile(
    r"^\s*stp\s+instance\s+(\S+)\s+priority\s+(\S+)", re.IGNORECASE,
)
_RE_HW_EDGE = re.compile(
    r"^\s*stp\s+edged-port\s+enable", re.IGNORECASE,
)
_RE_HW_BPDU = re.compile(
    r"^\s*stp\s+bpdu-protection", re.IGNORECASE,
)
_RE_HW_ROOT_PROTECT = re.compile(
    r"^\s*stp\s+root-protection", re.IGNORECASE,
)
_RE_HW_STP_COST = re.compile(
    r"^\s*stp\s+cost\s+(\S+)", re.IGNORECASE,
)
_RE_HW_STP_PORT_PRI = re.compile(
    r"^\s*stp\s+port\s+priority\s+(\S+)", re.IGNORECASE,
)

# ── H3C ───────────────────────────────────────────────────────────
_RE_H3C_STP_MODE = re.compile(
    r"^\s*stp\s+mode\s+(\S+)", re.IGNORECASE,
)
_RE_H3C_REGION = re.compile(
    r"^\s*stp\s+region-configuration", re.IGNORECASE,
)
_RE_H3C_ACTIVE = re.compile(
    r"^\s*active\s+region-configuration", re.IGNORECASE,
)
_RE_H3C_INSTANCE_VLAN = re.compile(
    r"^\s*instance\s+(\S+)\s+vlan\s+(.+)", re.IGNORECASE,
)
_RE_H3C_STP_INSTANCE_ROOT = re.compile(
    r"^\s*stp\s+instance\s+(\S+)\s+root\s+(primary|secondary)", re.IGNORECASE,
)
_RE_H3C_STP_INSTANCE_PRI = re.compile(
    r"^\s*stp\s+instance\s+(\S+)\s+priority\s+(\S+)", re.IGNORECASE,
)
_RE_H3C_EDGE = re.compile(
    r"^\s*stp\s+edged-port", re.IGNORECASE,
)
_RE_H3C_BPDU = re.compile(
    r"^\s*stp\s+bpdu-protection", re.IGNORECASE,
)
_RE_H3C_ROOT_PROTECT = re.compile(
    r"^\s*stp\s+root-protection", re.IGNORECASE,
)
_RE_H3C_STP_COST = re.compile(
    r"^\s*stp\s+cost\s+(\S+)", re.IGNORECASE,
)
_RE_H3C_STP_PORT_PRI = re.compile(
    r"^\s*stp\s+port\s+priority\s+(\S+)", re.IGNORECASE,
)

# ── Cisco ─────────────────────────────────────────────────────────
_RE_CISCO_STP_MODE = re.compile(
    r"^\s*spanning-tree\s+mode\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_MST_CFG = re.compile(
    r"^\s*spanning-tree\s+mst\s+configuration", re.IGNORECASE,
)
_RE_CISCO_INSTANCE_VLAN = re.compile(
    r"^\s*instance\s+(\S+)\s+vlan\s+(.+)", re.IGNORECASE,
)
_RE_CISCO_VLAN_PRI = re.compile(
    r"^\s*spanning-tree\s+vlan\s+(\S+)\s+priority\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_VLAN_ROOT = re.compile(
    r"^\s*spanning-tree\s+vlan\s+(\S+)\s+root\s+(primary|secondary)", re.IGNORECASE,
)
_RE_CISCO_PORTFAST = re.compile(
    r"^\s*spanning-tree\s+portfast", re.IGNORECASE,
)
_RE_CISCO_BPDU = re.compile(
    r"^\s*spanning-tree\s+bpduguard\s+enable", re.IGNORECASE,
)
_RE_CISCO_GUARD_ROOT = re.compile(
    r"^\s*spanning-tree\s+guard\s+root", re.IGNORECASE,
)
_RE_CISCO_STP_COST = re.compile(
    r"^\s*spanning-tree\s+cost\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_STP_PORT_PRI = re.compile(
    r"^\s*spanning-tree\s+port-priority\s+(\S+)", re.IGNORECASE,
)

_RE_INTERFACE = re.compile(
    r"^\s*interface\s+(\S+)", re.IGNORECASE,
)

_HW_VENDORS = {"huawei"}
_H3C_VENDORS = {"h3c"}
_CISCO_VENDORS = {"cisco"}


class StpAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "stp"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        lines = config_text.splitlines()
        vendor_lower = vendor.lower()
        is_hw = vendor_lower in _HW_VENDORS
        is_h3c = vendor_lower in _H3C_VENDORS
        is_cisco = vendor_lower in _CISCO_VENDORS

        if not is_hw and not is_h3c and not is_cisco:
            return FeatureAnalysis(
                feature="stp", status="skipped", risk_level="info",
                notes=[f"Vendor {vendor} not supported"],
            )

        if not self._has_stp_content(lines):
            return FeatureAnalysis(
                feature="stp", status="skipped", risk_level="info",
                notes=["未发现 STP 相关配置"],
            )

        result: Dict[str, Any] = {
            "mode": "",
            "instances": [],
            "interfaces": [],
        }
        missing: List[str] = []
        notes: List[str] = []

        if is_hw:
            self._parse_huawei(lines, result, missing, notes)
        elif is_h3c:
            self._parse_h3c(lines, result, missing, notes)
        elif is_cisco:
            self._parse_cisco(lines, result, missing, notes)

        if not result.get("instances") and not result.get("interfaces") and not result.get("mode") and "bpdu_guard" not in result and "root_guard" not in result:
            return FeatureAnalysis(
                feature="stp", status="skipped", risk_level="info",
                notes=["包含 STP 关键词但未识别到完整配置"],
            )

        has_fatal = any("fatal" in m for m in missing)
        risk = "info"
        if missing and not has_fatal:
            risk = "warning"
        if has_fatal:
            risk = "fatal"

        return FeatureAnalysis(
            feature="stp",
            status="analyzed",
            risk_level=risk,
            manual_review_required=risk in ("warning", "fatal"),
            rules=[result],
            references={},
            missing_context=missing,
            source_lines=[],
            notes=notes,
        )

    def _has_stp_content(self, lines) -> bool:
        keywords = [
            "stp enable", "stp mode", "stp region",
            "spanning-tree", "instance", "active region",
            "edged-port", "bpdu", "root-protection",
            "portfast", "bpduguard", "guard root",
        ]
        text = "\n".join(lines).lower()
        return any(k in text for k in keywords)

    @staticmethod
    def _find_or_create_instance(result, inst_id):
        for inst in result["instances"]:
            if inst["instance_id"] == inst_id:
                return inst
        inst = {"instance_id": inst_id, "vlans": [], "priority": "", "root_role": ""}
        result["instances"].append(inst)
        return inst

    @staticmethod
    def _find_or_create_iface(result, ifname):
        for iface in result["interfaces"]:
            if iface["interface"] == ifname:
                return iface
        iface = {
            "interface": ifname, "edge_port": False,
            "bpdu_guard": False, "root_guard": False,
            "cost": None, "priority": None,
        }
        result["interfaces"].append(iface)
        return iface

    def _parse_huawei(self, lines, result, missing, notes):
        current_if: Optional[str] = None
        in_region = False
        region_has_active = False

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            m = _RE_HW_STP_MODE.match(stripped)
            if m:
                result["mode"] = m.group(1).lower()
                continue

            m = _RE_HW_STP_INSTANCE_ROOT.match(stripped)
            if m:
                inst = self._find_or_create_instance(result, m.group(1))
                inst["root_role"] = m.group(2).lower()
                continue

            m = _RE_HW_STP_INSTANCE_PRI.match(stripped)
            if m:
                inst = self._find_or_create_instance(result, m.group(1))
                inst["priority"] = m.group(2)
                continue

            m = _RE_HW_BPDU.match(stripped)
            if m:
                result["bpdu_guard"] = True
                continue

            m = _RE_HW_ROOT_PROTECT.match(stripped)
            if m:
                result["root_guard"] = True
                continue

            if _RE_HW_EDGE.match(stripped):
                if current_if:
                    self._find_or_create_iface(result, current_if)["edge_port"] = True
                continue

            m = _RE_HW_STP_COST.match(stripped)
            if m and current_if:
                self._find_or_create_iface(result, current_if)["cost"] = m.group(1)
                continue

            m = _RE_HW_STP_PORT_PRI.match(stripped)
            if m and current_if:
                self._find_or_create_iface(result, current_if)["priority"] = m.group(1)
                continue

            m = _RE_HW_REGION.match(stripped)
            if m:
                in_region = True
                continue

            if in_region:
                if _RE_HW_ACTIVE.match(stripped):
                    region_has_active = True
                    in_region = False
                    continue
                mm = _RE_HW_INSTANCE_VLAN.match(stripped)
                if mm:
                    inst = self._find_or_create_instance(result, mm.group(1))
                    inst["vlans"] = self._parse_vlan_list(mm.group(2))
                    continue
                if not raw.startswith(" ") and stripped[0].isalpha():
                    in_region = False
                    continue
                continue

            m = _RE_INTERFACE.match(stripped)
            if m:
                current_if = m.group(1)
                continue

        if in_region and not region_has_active:
            missing.append("MSTP region 配置缺少 active region-configuration——warning")

    def _parse_h3c(self, lines, result, missing, notes):
        current_if: Optional[str] = None
        in_region = False
        region_has_active = False

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            m = _RE_H3C_STP_MODE.match(stripped)
            if m:
                result["mode"] = m.group(1).lower()
                continue

            m = _RE_H3C_STP_INSTANCE_ROOT.match(stripped)
            if m:
                inst = self._find_or_create_instance(result, m.group(1))
                inst["root_role"] = m.group(2).lower()
                continue

            m = _RE_H3C_STP_INSTANCE_PRI.match(stripped)
            if m:
                inst = self._find_or_create_instance(result, m.group(1))
                inst["priority"] = m.group(2)
                continue

            m = _RE_H3C_BPDU.match(stripped)
            if m:
                result["bpdu_guard"] = True
                continue

            m = _RE_H3C_ROOT_PROTECT.match(stripped)
            if m:
                result["root_guard"] = True
                continue

            if _RE_H3C_EDGE.match(stripped):
                if current_if:
                    self._find_or_create_iface(result, current_if)["edge_port"] = True
                continue

            m = _RE_H3C_STP_COST.match(stripped)
            if m and current_if:
                self._find_or_create_iface(result, current_if)["cost"] = m.group(1)
                continue

            m = _RE_H3C_STP_PORT_PRI.match(stripped)
            if m and current_if:
                self._find_or_create_iface(result, current_if)["priority"] = m.group(1)
                continue

            m = _RE_H3C_REGION.match(stripped)
            if m:
                in_region = True
                continue

            if in_region:
                if _RE_H3C_ACTIVE.match(stripped):
                    region_has_active = True
                    in_region = False
                    continue
                mm = _RE_H3C_INSTANCE_VLAN.match(stripped)
                if mm:
                    inst = self._find_or_create_instance(result, mm.group(1))
                    inst["vlans"] = self._parse_vlan_list(mm.group(2))
                    continue
                if not raw.startswith(" ") and stripped[0].isalpha():
                    in_region = False
                    continue
                continue

            m = _RE_INTERFACE.match(stripped)
            if m:
                current_if = m.group(1)
                continue

        if in_region and not region_has_active:
            missing.append("MSTP region 配置缺少 active region-configuration——warning")

    def _parse_cisco(self, lines, result, missing, notes):
        current_if: Optional[str] = None
        in_mst_cfg = False

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            m = _RE_CISCO_STP_MODE.match(stripped)
            if m:
                result["mode"] = m.group(1).lower()
                continue

            m = _RE_CISCO_VLAN_PRI.match(stripped)
            if m:
                inst = self._find_or_create_instance(result, m.group(1))
                inst["priority"] = m.group(2)
                continue

            m = _RE_CISCO_VLAN_ROOT.match(stripped)
            if m:
                inst = self._find_or_create_instance(result, m.group(1))
                inst["root_role"] = m.group(2).lower()
                continue

            m = _RE_CISCO_BPDU.match(stripped)
            if m:
                if current_if:
                    self._find_or_create_iface(result, current_if)["bpdu_guard"] = True
                else:
                    result["bpdu_guard"] = True
                continue

            m = _RE_CISCO_GUARD_ROOT.match(stripped)
            if m:
                if current_if:
                    self._find_or_create_iface(result, current_if)["root_guard"] = True
                else:
                    result["root_guard"] = True
                continue

            if _RE_CISCO_PORTFAST.match(stripped):
                if current_if:
                    self._find_or_create_iface(result, current_if)["edge_port"] = True
                continue

            m = _RE_CISCO_STP_COST.match(stripped)
            if m and current_if:
                self._find_or_create_iface(result, current_if)["cost"] = m.group(1)
                continue

            m = _RE_CISCO_STP_PORT_PRI.match(stripped)
            if m and current_if:
                self._find_or_create_iface(result, current_if)["priority"] = m.group(1)
                continue

            m = _RE_CISCO_MST_CFG.match(stripped)
            if m:
                in_mst_cfg = True
                continue

            if in_mst_cfg:
                mm = _RE_CISCO_INSTANCE_VLAN.match(stripped)
                if mm:
                    inst = self._find_or_create_instance(result, mm.group(1))
                    inst["vlans"] = self._parse_vlan_list(mm.group(2))
                    continue
                if not raw.startswith(" ") and stripped[0].isalpha():
                    in_mst_cfg = False
                    continue
                continue

            m = _RE_INTERFACE.match(stripped)
            if m:
                current_if = m.group(1)
                continue

    @staticmethod
    def _parse_vlan_list(vlan_str: str) -> List[str]:
        parts = vlan_str.replace(",", " ").split()
        return [p.strip() for p in parts if p.strip()]
