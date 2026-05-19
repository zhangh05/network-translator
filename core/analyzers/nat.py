from __future__ import annotations
import re
from typing import Any, Dict, List, Set

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer


_INTERFACE_NAT_MARKING_CISCO = re.compile(r"^\s*ip nat\s+(inside|outside)\s*$", re.IGNORECASE)
_CISCO_SOURCE_LIST = re.compile(
    r"^\s*ip nat inside source list\s+(\S+)\s+"
    r"(?:interface\s+(\S+)(?:\s+overload)?|pool\s+(\S+))\s*$",
    re.IGNORECASE,
)
_CISCO_STATIC = re.compile(
    r"^\s*ip nat inside source static\s+(\S+)\s+(\S+)",
    re.IGNORECASE,
)
_CISCO_OUTSIDE = re.compile(r"^\s*ip nat outside source .+", re.IGNORECASE)

_HW_NAT_OUTBOUND = re.compile(r"^\s*nat\s+outbound\s+(\S+)", re.IGNORECASE)
_HW_NAT_SERVER = re.compile(
    r"^\s*nat\s+server\s+protocol\s+tcp\s+global\s+(\S+)\s+(\d+)\s+inside\s+(\S+)\s+(\d+)",
    re.IGNORECASE,
)
_HW_NAT_SERVER_UDP = re.compile(
    r"^\s*nat\s+server\s+protocol\s+udp\s+global\s+(\S+)\s+(\d+)\s+inside\s+(\S+)\s+(\d+)",
    re.IGNORECASE,
)
_HW_NAT_STATIC = re.compile(r"^\s*nat\s+static\s+.*?global\s+(\S+)\s+inside\s+(\S+)", re.IGNORECASE)
_HW_NAT_ADDR_GROUP = re.compile(r"^\s*nat\s+address-group\s+(\S+)", re.IGNORECASE)

_FW_SOURCE_ZONE = re.compile(r"^\s*source-zone\s+(\S+)", re.IGNORECASE)
_FW_DEST_ZONE = re.compile(r"^\s*destination-zone\s+(\S+)", re.IGNORECASE)
_FW_NAT_POLICY = re.compile(r"^\s*nat-policy\b", re.IGNORECASE)
_FW_ACTION_SOURCE_NAT = re.compile(r"^\s*action\s+source-nat\b", re.IGNORECASE)
_FW_ACTION_DEST_NAT = re.compile(r"^\s*action\s+destination-nat\b", re.IGNORECASE)
_FW_EASY_IP = re.compile(r"easy-ip", re.IGNORECASE)
_FW_ADDRESS_SET = re.compile(r"^\s*address-set\s+(\S+)", re.IGNORECASE)
_FW_SERVICE_SET = re.compile(r"^\s*service-set\s+(\S+)", re.IGNORECASE)
_FW_ASA_NAT = re.compile(r"^\s*nat\s+\(.+?,.+?\)", re.IGNORECASE)

_ACL_DEFINITION = re.compile(r"^\s*(?:acl\s+(?:number\s+)?|access-list\s+)(\S+)", re.IGNORECASE | re.MULTILINE)

_RULE_ID = iter(str(i) for i in range(1, 1000))


def _next_rule_id() -> str:
    return f"auto-{next(_RULE_ID)}"


def _reset_rule_id():
    global _RULE_ID
    _RULE_ID = iter(str(i) for i in range(1, 1000))


def _collect_acls(config_text: str) -> Set[str]:
    return set(m.group(1) for m in _ACL_DEFINITION.finditer(config_text))


def _detect_interface_nat_marking(config_lines: List[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    current_intf = None
    for line in config_lines:
        m = re.match(r"^\s*interface\s+(\S+)", line, re.IGNORECASE)
        if m:
            current_intf = m.group(1)
            continue
        if current_intf:
            m2 = _INTERFACE_NAT_MARKING_CISCO.match(line)
            if m2:
                result[current_intf] = m2.group(1).lower()
    return result


def _classify_risk(missing: List[str], nat_type: str, platform_hint: str) -> str:
    if nat_type == "unknown":
        return "fatal"
    if not missing:
        return "info"
    fatal_keywords = ["NAT 类型无法判断", "缺少方向", "目标 platform unknown"]
    for item in missing:
        for kw in fatal_keywords:
            if kw in item:
                return "fatal"
    return "warning"


class NatAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "nat"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        _reset_rule_id()
        lines = config_text.splitlines()
        config_lines = [l.strip() for l in lines if l.strip()]
        defined_acls = _collect_acls(config_text)
        intf_nat_marking = _detect_interface_nat_marking(lines)

        missing: List[str] = []
        rules: List[Dict[str, Any]] = []
        source_lines: List[str] = []
        platform_hint = domain if domain in ("routing", "firewall") else "unknown"

        vendor_lower = vendor.lower()
        is_cisco = vendor_lower in ("cisco",)
        is_huawei = vendor_lower in ("huawei",)
        is_h3c = vendor_lower in ("h3c",)

        cisco_nat_any = False
        hw_nat_any = False
        fw_nat_any = False

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            matched = False

            # ── Cisco routing NAT ─────────────────────────────────
            if is_cisco and not matched:
                m = _CISCO_SOURCE_LIST.match(line)
                if m:
                    cisco_nat_any = True
                    matched = True
                    acl_ref = m.group(1)
                    egress = m.group(2)
                    pool = m.group(3)
                    is_pat = "overload" in line.lower() or egress is not None

                    refs: Dict[str, Any] = {"acl": [], "pool": []}
                    if acl_ref not in defined_acls:
                        missing.append(f"ACL {acl_ref} 未在输入中定义")
                    refs["acl"] = [acl_ref]
                    if egress:
                        nat_type = "pat"
                        refs["pool"] = []
                    elif pool:
                        nat_type = "source_nat"
                        refs["pool"] = [pool]
                        if pool not in config_text:
                            missing.append(f"NAT pool {pool} 未在输入中定义")
                    else:
                        nat_type = "source_nat"

                    rules.append({
                        "rule_id": _next_rule_id(),
                        "nat_type": nat_type,
                        "source": "",
                        "destination": "",
                        "service": "",
                        "translated_address": egress or pool or "",
                        "egress_interface": egress or "",
                        "source_zone": "",
                        "destination_zone": "",
                        "references": refs,
                        "source_lines": [line],
                    })
                    source_lines.append(line)
                    continue

                m = _CISCO_STATIC.match(line)
                if m:
                    cisco_nat_any = True
                    matched = True
                    inside_ip, outside_ip = m.group(1), m.group(2)
                    rules.append({
                        "rule_id": _next_rule_id(),
                        "nat_type": "static_nat",
                        "source": inside_ip,
                        "destination": "",
                        "service": "",
                        "translated_address": outside_ip,
                        "egress_interface": "",
                        "source_zone": "",
                        "destination_zone": "",
                        "references": {"acl": [], "pool": []},
                        "source_lines": [line],
                    })
                    source_lines.append(line)
                    continue

                m = _CISCO_OUTSIDE.match(line)
                if m:
                    cisco_nat_any = True
                    matched = True
                    rules.append({
                        "rule_id": _next_rule_id(),
                        "nat_type": "source_nat",
                        "source": "",
                        "destination": "",
                        "service": "",
                        "translated_address": "",
                        "egress_interface": "",
                        "source_zone": "",
                        "destination_zone": "",
                        "references": {"acl": [], "pool": []},
                        "source_lines": [line],
                    })
                    source_lines.append(line)

            # ── Huawei / H3C routing NAT ─────────────────────────
            if (is_huawei or is_h3c) and not matched:
                m = _HW_NAT_OUTBOUND.match(line)
                if m:
                    hw_nat_any = True
                    matched = True
                    acl_ref = m.group(1)
                    refs: Dict[str, Any] = {"acl": [acl_ref], "pool": []}
                    if acl_ref not in defined_acls:
                        missing.append(f"ACL {acl_ref} 未在输入中定义")
                    rules.append({
                        "rule_id": _next_rule_id(),
                        "nat_type": "pat" if "overload" in line.lower() else "source_nat",
                        "source": "",
                        "destination": "",
                        "service": "",
                        "translated_address": "",
                        "egress_interface": "",
                        "source_zone": "",
                        "destination_zone": "",
                        "references": refs,
                        "source_lines": [line],
                    })
                    source_lines.append(line)
                    continue

                for _pat in (_HW_NAT_SERVER, _HW_NAT_SERVER_UDP):
                    m = _pat.match(line)
                    if m:
                        hw_nat_any = True
                        matched = True
                        global_ip, global_port, inside_ip, inside_port = m.group(1), m.group(2), m.group(3), m.group(4)
                        rules.append({
                            "rule_id": _next_rule_id(),
                            "nat_type": "destination_nat",
                            "source": inside_ip,
                            "destination": global_ip,
                            "service": f"{inside_port}",
                            "translated_address": inside_ip,
                            "egress_interface": "",
                            "source_zone": "",
                            "destination_zone": "",
                            "references": {"acl": [], "pool": []},
                            "source_lines": [line],
                        })
                        source_lines.append(line)
                        continue

                m = _HW_NAT_STATIC.match(line)
                if m:
                    hw_nat_any = True
                    matched = True
                    rules.append({
                        "rule_id": _next_rule_id(),
                        "nat_type": "static_nat",
                        "source": m.group(2),
                        "destination": "",
                        "service": "",
                        "translated_address": m.group(1),
                        "egress_interface": "",
                        "source_zone": "",
                        "destination_zone": "",
                        "references": {"acl": [], "pool": []},
                        "source_lines": [line],
                    })
                    source_lines.append(line)

            # ── Firewall NAT (vendor-agnostic) ───────────────────
            if not matched:
                m = _FW_NAT_POLICY.match(line)
                if m:
                    fw_nat_any = True
                    matched = True

            if not matched:
                m_sz = _FW_SOURCE_ZONE.match(line)
                m_dz = _FW_DEST_ZONE.match(line)
                if m_sz or m_dz:
                    fw_nat_any = True

        # ── Consolidate firewall nat-policy entries ──────────────
        if fw_nat_any:
            fw_rule: Dict[str, Any] = {
                "rule_id": _next_rule_id(),
                "nat_type": "policy_nat",
                "source": "",
                "destination": "",
                "service": "",
                "translated_address": "",
                "egress_interface": "",
                "source_zone": "",
                "destination_zone": "",
                "references": {"acl": [], "address_object": [], "service_object": [], "pool": []},
                "source_lines": [],
            }
            for raw_line in lines:
                line = raw_line.strip()
                m = _FW_SOURCE_ZONE.match(line)
                if m:
                    fw_rule["source_zone"] = m.group(1)
                    fw_rule["source_lines"].append(line)
                    continue
                m = _FW_DEST_ZONE.match(line)
                if m:
                    fw_rule["destination_zone"] = m.group(1)
                    fw_rule["source_lines"].append(line)
                    continue
                m = _FW_ADDRESS_SET.match(line)
                if m:
                    fw_rule["references"]["address_object"].append(m.group(1))
                    fw_rule["source_lines"].append(line)
                    continue
                m = _FW_SERVICE_SET.match(line)
                if m:
                    fw_rule["references"]["service_object"].append(m.group(1))
                    fw_rule["source_lines"].append(line)
                    continue
                m = _FW_ACTION_SOURCE_NAT.match(line)
                if m:
                    fw_rule["nat_type"] = "source_nat" if "easy-ip" in line.lower() else "policy_nat"
                    fw_rule["source_lines"].append(line)
                    continue
                m = _FW_ACTION_DEST_NAT.match(line)
                if m:
                    fw_rule["nat_type"] = "destination_nat"
                    fw_rule["source_lines"].append(line)
            if fw_rule["source_lines"]:
                rules.append(fw_rule)
                source_lines.extend(fw_rule["source_lines"])

        # ── Missing interface marking (Cisco) ────────────────────
        if cisco_nat_any and not intf_nat_marking:
            missing.append("缺少 Cisco 接口 ip nat inside/outside 方向标记")
        if cisco_nat_any and intf_nat_marking:
            has_inside = any(v == "inside" for v in intf_nat_marking.values())
            has_outside = any(v == "outside" for v in intf_nat_marking.values())
            if not has_inside:
                missing.append("缺少 inside 接口标记")
            if not has_outside:
                missing.append("缺少 outside 接口标记")

        # ── No NAT rules found ───────────────────────────────────
        if not rules and not cisco_nat_any and not hw_nat_any and not fw_nat_any:
            return FeatureAnalysis(
                feature="nat",
                status="skipped",
                risk_level="info",
                notes=["未发现 NAT 配置"],
            )

        status = "analyzed"
        manual_review = True

        nat_types = {r["nat_type"] for r in rules}
        if len(nat_types) == 1:
            nat_type = nat_types.pop()
        else:
            nat_type = "mixed"

        risk = _classify_risk(missing, nat_type, platform_hint)

        # ── Missing egress hint for routing NAT ──────────────────
        if cisco_nat_any or hw_nat_any:
            has_egress = any(bool(r.get("egress_interface")) for r in rules)
            if not has_egress and nat_type in ("source_nat", "pat", "mixed"):
                if not any("出接口" in m for m in missing):
                    missing.append("缺少 NAT 出接口")

        metadata = {"platform_hint": platform_hint}

        return FeatureAnalysis(
            feature="nat",
            status=status,
            risk_level=risk,
            manual_review_required=manual_review,
            rules=rules,
            missing_context=missing,
            source_lines=source_lines,
            metadata=metadata,
        )
