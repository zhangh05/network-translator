from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer


# ── Huawei ────────────────────────────────────────────────────────
_RE_HW_ETH_TRUNK = re.compile(
    r"^\s*interface\s+Eth-Trunk\s*(\S+)", re.IGNORECASE,
)
_RE_HW_MODE = re.compile(
    r"^\s*mode\s+(.+)", re.IGNORECASE,
)
_RE_HW_TRUNKPORT = re.compile(
    r"^\s*trunkport\s+(\S+)", re.IGNORECASE,
)
_RE_HW_ETH_TRUNK_PORT = re.compile(
    r"^\s*eth-trunk\s+(\S+)", re.IGNORECASE,
)
_RE_HW_LACP_PRIORITY = re.compile(
    r"^\s*lacp\s+priority\s+(\S+)", re.IGNORECASE,
)
_RE_HW_LACP_TIMEOUT = re.compile(
    r"^\s*lacp\s+timeout\s+(\S+)", re.IGNORECASE,
)
_RE_HW_LOAD_BALANCE = re.compile(
    r"^\s*load-balance\s+(\S+)", re.IGNORECASE,
)
_RE_HW_LACP_PREEMPT = re.compile(
    r"^\s*lacp\s+preempt", re.IGNORECASE,
)

# ── H3C ───────────────────────────────────────────────────────────
_RE_H3C_BRIDGE_AGG = re.compile(
    r"^\s*interface\s+Bridge-Aggregation\s*(\S+)", re.IGNORECASE,
)
_RE_H3C_LAG_MODE = re.compile(
    r"^\s*link-aggregation\s+mode\s+(\S+)", re.IGNORECASE,
)
_RE_H3C_PORT_LAG_GROUP = re.compile(
    r"^\s*port\s+link-aggregation\s+group\s+(\S+)", re.IGNORECASE,
)
_RE_H3C_SELECTED_PORT = re.compile(
    r"^\s*link-aggregation\s+selected-port\s+minimum\s+(\S+)", re.IGNORECASE,
)
_RE_H3C_LACP_PERIOD = re.compile(
    r"^\s*lacp\s+period\s+short", re.IGNORECASE,
)

# ── Cisco ─────────────────────────────────────────────────────────
_RE_CISCO_PORT_CHANNEL = re.compile(
    r"^\s*interface\s+Port-channel\s*(\S+)", re.IGNORECASE,
)
_RE_CISCO_CHANNEL_GROUP = re.compile(
    r"^\s*channel-group\s+(\S+)\s+mode\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_CHANNEL_GROUP_NO_MODE = re.compile(
    r"^\s*channel-group\s+(\S+)\s*$", re.IGNORECASE,
)
_RE_CISCO_LACP_RATE = re.compile(
    r"^\s*lacp\s+rate\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_LACP_PORT_PRI = re.compile(
    r"^\s*lacp\s+port-priority\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_PC_LOAD_BALANCE = re.compile(
    r"^\s*port-channel\s+load-balance\s+(.+)", re.IGNORECASE,
)
_RE_CISCO_INTERFACE_RANGE = re.compile(
    r"^\s*interface\s+range\s+(.+)", re.IGNORECASE,
)

_RE_INTERFACE = re.compile(
    r"^\s*interface\s+(\S+)", re.IGNORECASE,
)

_HW_VENDORS = {"huawei"}
_H3C_VENDORS = {"h3c"}
_CISCO_VENDORS = {"cisco"}


class LacpAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "lacp"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        lines = config_text.splitlines()
        vendor_lower = vendor.lower()
        is_hw = vendor_lower in _HW_VENDORS
        is_h3c = vendor_lower in _H3C_VENDORS
        is_cisco = vendor_lower in _CISCO_VENDORS

        if not is_hw and not is_h3c and not is_cisco:
            return FeatureAnalysis(
                feature="lacp", status="skipped", risk_level="info",
                notes=[f"Vendor {vendor} not supported"],
            )

        if not self._has_lacp_content(lines):
            return FeatureAnalysis(
                feature="lacp", status="skipped", risk_level="info",
                notes=["未发现链路聚合相关配置"],
            )

        aggregates: List[Dict] = []
        refs: Dict[str, List[str]] = {"interfaces": []}
        missing: List[str] = []
        member_to_groups: Dict[str, List[str]] = {}

        if is_hw:
            self._parse_huawei(lines, aggregates, refs, missing, member_to_groups)
        elif is_h3c:
            self._parse_h3c(lines, aggregates, refs, missing, member_to_groups)
        elif is_cisco:
            self._parse_cisco(lines, aggregates, refs, missing, member_to_groups)

        # ── Cross-reference checks ──
        self._cross_ref(aggregates, refs, missing, member_to_groups)

        if not aggregates:
            if member_to_groups:
                return FeatureAnalysis(
                    feature="lacp", status="analyzed",
                    risk_level="warning",
                    manual_review_required=True,
                    missing_context=["存在成员接口绑定聚合组，但未定义对应聚合接口——warning"],
                    references=refs,
                    notes=[],
                )
            return FeatureAnalysis(
                feature="lacp", status="skipped", risk_level="info",
                notes=["包含 LACP 关键词但未识别到完整聚合配置"],
            )

        has_fatal = any("fatal" in m for m in missing)
        risk = "info"
        if missing and not has_fatal:
            risk = "warning"
        if has_fatal:
            risk = "fatal"

        return FeatureAnalysis(
            feature="lacp",
            status="analyzed",
            risk_level=risk,
            manual_review_required=risk in ("warning", "fatal"),
            rules=aggregates,
            references=refs,
            missing_context=missing,
            source_lines=[],
            notes=[],
        )

    def _has_lacp_content(self, lines) -> bool:
        keywords = [
            "eth-trunk", "Bridge-Aggregation", "Port-channel",
            "trunkport", "channel-group", "lacp",
            "link-aggregation",
        ]
        for l in lines:
            ll = l.lower()
            if any(k.lower() in ll for k in keywords):
                return True
        return False

    def _parse_huawei(self, lines, aggregates, refs, missing, member_to_groups):
        current_agg: Optional[Dict] = None
        current_if: Optional[str] = None
        agg_by_id: Dict[str, Dict] = {}

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            m = _RE_HW_ETH_TRUNK.match(stripped)
            if m:
                gid = m.group(1)
                if gid in agg_by_id:
                    current_agg = agg_by_id[gid]
                else:
                    current_agg = {
                        "aggregate_interface": f"Eth-Trunk{gid}",
                        "group_id": gid,
                        "mode": "unknown",
                        "members": [],
                        "load_balance": "",
                        "lacp_rate": "",
                        "min_links": "",
                    }
                    agg_by_id[gid] = current_agg
                current_if = current_agg["aggregate_interface"]
                continue

            if current_agg is not None:
                mm = _RE_HW_MODE.match(stripped)
                if mm:
                    current_agg["mode"] = mm.group(1).strip()
                    continue
                mm = _RE_HW_TRUNKPORT.match(stripped)
                if mm:
                    member = mm.group(1)
                    current_agg["members"].append(member)
                    refs.setdefault("interfaces", []).append(member)
                    member_to_groups.setdefault(member, []).append(current_agg["group_id"])
                    continue
                mm = _RE_HW_LOAD_BALANCE.match(stripped)
                if mm:
                    current_agg["load_balance"] = mm.group(1).strip()
                    continue
                mm = _RE_HW_LACP_PRIORITY.match(stripped)
                if mm:
                    current_agg["lacp_priority"] = mm.group(1)
                    continue
                mm = _RE_HW_LACP_TIMEOUT.match(stripped)
                if mm:
                    current_agg["lacp_rate"] = mm.group(1)
                    continue
                mm = _RE_HW_LACP_PREEMPT.match(stripped)
                if mm:
                    current_agg["preempt"] = "yes"
                    continue

            m = _RE_HW_ETH_TRUNK_PORT.match(stripped)
            if m:
                member_gid = m.group(1)
                member_if = current_if or "unknown"
                member_to_groups.setdefault(member_if, []).append(member_gid)
                if member_gid in agg_by_id:
                    agg_by_id[member_gid]["members"].append(member_if)
                    refs.setdefault("interfaces", []).append(member_if)
                continue

            m = _RE_INTERFACE.match(stripped)
            if m:
                current_if = m.group(1)
                if current_agg is not None and not raw.startswith(" "):
                    current_agg = None
                continue

            if current_agg is not None and not raw.startswith(" ") and stripped[0].isalpha():
                current_agg = None

        aggregates.extend(agg_by_id.values())

    def _parse_h3c(self, lines, aggregates, refs, missing, member_to_groups):
        current_agg: Optional[Dict] = None
        current_if: Optional[str] = None
        agg_by_id: Dict[str, Dict] = {}

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            m = _RE_H3C_BRIDGE_AGG.match(stripped)
            if m:
                gid = m.group(1)
                if gid in agg_by_id:
                    current_agg = agg_by_id[gid]
                else:
                    current_agg = {
                        "aggregate_interface": f"Bridge-Aggregation{gid}",
                        "group_id": gid,
                        "mode": "unknown",
                        "members": [],
                        "load_balance": "",
                        "lacp_rate": "",
                        "min_links": "",
                    }
                    agg_by_id[gid] = current_agg
                current_if = current_agg["aggregate_interface"]
                continue

            if current_agg is not None:
                mm = _RE_H3C_LAG_MODE.match(stripped)
                if mm:
                    current_agg["mode"] = mm.group(1).strip()
                    continue
                mm = _RE_H3C_SELECTED_PORT.match(stripped)
                if mm:
                    current_agg["min_links"] = mm.group(1)
                    continue
                mm = _RE_H3C_LACP_PERIOD.match(stripped)
                if mm:
                    current_agg["lacp_rate"] = "fast"
                    continue

            m = _RE_H3C_PORT_LAG_GROUP.match(stripped)
            if m:
                member_gid = m.group(1)
                member_if = current_if or "unknown"
                member_to_groups.setdefault(member_if, []).append(member_gid)
                if member_gid in agg_by_id:
                    agg_by_id[member_gid]["members"].append(member_if)
                    refs.setdefault("interfaces", []).append(member_if)
                continue

            m = _RE_INTERFACE.match(stripped)
            if m:
                current_if = m.group(1)
                if current_agg is not None and not raw.startswith(" "):
                    current_agg = None
                continue

            if current_agg is not None and not raw.startswith(" ") and stripped[0].isalpha():
                current_agg = None

        aggregates.extend(agg_by_id.values())

    def _parse_cisco(self, lines, aggregates, refs, missing, member_to_groups):
        current_agg: Optional[Dict] = None
        current_if: Optional[str] = None
        agg_by_id: Dict[str, Dict] = {}

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            m = _RE_CISCO_PORT_CHANNEL.match(stripped)
            if m:
                gid = m.group(1)
                if gid in agg_by_id:
                    current_agg = agg_by_id[gid]
                else:
                    current_agg = {
                        "aggregate_interface": f"Port-channel{gid}",
                        "group_id": gid,
                        "mode": "unknown",
                        "members": [],
                        "load_balance": "",
                        "lacp_rate": "",
                        "min_links": "",
                    }
                    agg_by_id[gid] = current_agg
                current_if = current_agg["aggregate_interface"]
                continue

            if current_agg is not None:
                mm = _RE_CISCO_PC_LOAD_BALANCE.match(stripped)
                if mm:
                    current_agg["load_balance"] = mm.group(1).strip()
                    continue

            # channel-group on member interface
            mm = _RE_CISCO_CHANNEL_GROUP.match(stripped)
            if mm:
                member_gid = mm.group(1)
                mode = mm.group(2).lower()
                member_if = current_if or "unknown"
                member_to_groups.setdefault(member_if, []).append(member_gid)
                if member_gid in agg_by_id:
                    agg_by_id[member_gid]["members"].append(member_if)
                    refs.setdefault("interfaces", []).append(member_if)
                    if agg_by_id[member_gid]["mode"] == "unknown":
                        agg_by_id[member_gid]["mode"] = mode
                continue

            mm = _RE_CISCO_CHANNEL_GROUP_NO_MODE.match(stripped)
            if mm:
                member_gid = mm.group(1)
                member_if = current_if or "unknown"
                member_to_groups.setdefault(member_if, []).append(member_gid)
                if member_gid in agg_by_id:
                    agg_by_id[member_gid]["members"].append(member_if)
                    refs.setdefault("interfaces", []).append(member_if)
                continue

            if current_agg is not None:
                mm = _RE_CISCO_LACP_RATE.match(stripped)
                if mm:
                    current_agg["lacp_rate"] = mm.group(1).strip()
                    continue

            m = _RE_CISCO_INTERFACE_RANGE.match(stripped)
            if m:
                missing.append(f"interface range {m.group(1)} 无法完全展开，请手动验证成员接口——warning")
                continue

            m = _RE_INTERFACE.match(stripped)
            if m:
                current_if = m.group(1)
                if current_agg is not None and not raw.startswith(" "):
                    current_agg = None
                continue

            if current_agg is not None and not raw.startswith(" ") and stripped[0].isalpha():
                current_agg = None

        aggregates.extend(agg_by_id.values())

    @staticmethod
    def _cross_ref(aggregates, refs, missing, member_to_groups):
        defined_group_ids = {a["group_id"] for a in aggregates}
        all_member_ifs = set()

        for a in aggregates:
            if not a["members"]:
                missing.append(f"聚合接口 {a['aggregate_interface']} 未发现成员接口——warning")
            for m in a["members"]:
                all_member_ifs.add(m)

        # Check for members referencing undefined groups
        for member, groups in member_to_groups.items():
            if len(set(groups)) > 1:
                missing.append(
                    f"接口 {member} 绑定了多个聚合组 ({', '.join(set(groups))})——fatal",
                )
            for g in set(groups):
                if g not in defined_group_ids:
                    missing.append(
                        f"接口 {member} 引用了未定义的聚合组 ID {g}——warning",
                    )
