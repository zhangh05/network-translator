from __future__ import annotations
import re
from typing import Any, Dict, List

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer

# ── Huawei USG security-policy ────────────────────────────────────────────────
_HW_POLICY_START = re.compile(r"^\s*security-policy\s*$", re.IGNORECASE)
_HW_RULE_NAME = re.compile(r"^\s*rule\s+name\s+(\S+)", re.IGNORECASE)
_HW_SOURCE_ZONE = re.compile(r"^\s*source-zone\s+(\S+)", re.IGNORECASE)
_HW_DEST_ZONE = re.compile(r"^\s*destination-zone\s+(\S+)", re.IGNORECASE)
_HW_SOURCE_ADDR = re.compile(r"^\s*source-address\s+(\S+)(?:\s+mask\s+(\S+))?", re.IGNORECASE)
_HW_DEST_ADDR = re.compile(r"^\s*destination-address\s+(\S+)(?:\s+mask\s+(\S+))?", re.IGNORECASE)
_HW_SOURCE_ADDR_SET = re.compile(r"^\s*source-address-set\s+(\S+)", re.IGNORECASE)
_HW_DEST_ADDR_SET = re.compile(r"^\s*destination-address-set\s+(\S+)", re.IGNORECASE)
_HW_SERVICE = re.compile(r"^\s*service\s+(\S+)", re.IGNORECASE)
_HW_SERVICE_SET = re.compile(r"^\s*service-set\s+(\S+)", re.IGNORECASE)
_HW_ACTION = re.compile(r"^\s*action\s+(permit|deny|drop)", re.IGNORECASE)
_HW_APPLICATION = re.compile(r"^\s*application\s+(\S+)", re.IGNORECASE)
_HW_USER = re.compile(r"^\s*user\s+(\S+)", re.IGNORECASE)
_HW_TIME_RANGE = re.compile(r"^\s*time-range\s+(\S+)", re.IGNORECASE)
_HW_LOG = re.compile(r"^\s*logging\b", re.IGNORECASE)

# ── H3C security-policy ip ────────────────────────────────────────────────────
_H3_POLICY_IP = re.compile(r"^\s*security-policy\s+ip\s*$", re.IGNORECASE)
_H3_RULE = re.compile(r"^\s*rule\s+(\d+)(?:\s+name\s+(\S+))?", re.IGNORECASE)
_H3_SOURCE_ZONE = _HW_SOURCE_ZONE
_H3_DEST_ZONE = _HW_DEST_ZONE
_H3_SOURCE_IP = re.compile(r"^\s*source-ip\s+(\S+)(?:\s+(\S+))?", re.IGNORECASE)
_H3_DEST_IP = re.compile(r"^\s*destination-ip\s+(\S+)(?:\s+(\S+))?", re.IGNORECASE)
_H3_SERVICE = re.compile(r"^\s*service\s+(\S+)", re.IGNORECASE)
_H3_ACTION = re.compile(r"^\s*action\s+(pass|drop)", re.IGNORECASE)
_H3_LOG = re.compile(r"^\s*logging\b", re.IGNORECASE)

# ── Cisco ASA access-list (inferred security-policy) ──────────────────────────
_ASA_ACL_LINE = re.compile(
    r"^\s*access-list\s+(\S+)\s+extended\s+"
    r"(permit|deny)\s+"
    r"(ip|tcp|udp|icmp|object-group\S+)\s+"
    r"(.+?)\s+(\S+(?:\s+\S+)?(?:\s+eq\s+\S+)?)",
    re.IGNORECASE,
)
_ASA_ACCESS_GROUP = re.compile(
    r"^\s*access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)",
    re.IGNORECASE,
)
_ASA_OBJECT_NETWORK = re.compile(r"^\s*object\s+network\s+(\S+)", re.IGNORECASE)
_ASA_OBJECT_GROUP = re.compile(r"^\s*object-group\s+\S+\s+(\S+)", re.IGNORECASE)
_ASA_HOST = re.compile(r"^\s*host\s+(\S+)", re.IGNORECASE)
_ASA_SUBNET = re.compile(r"^\s*subnet\s+(\S+)\s+(\S+)", re.IGNORECASE)
_ASA_NETWORK = re.compile(r"^\s*network\s+(\S+)\s+(\S+)", re.IGNORECASE)
_ASA_SERVICE_OBJECT = re.compile(
    r"^\s*service-object\s+(tcp|udp)(?:\s+(source\s+)?\S+)?(?:\s+(\d+))?",
    re.IGNORECASE,
)


_RULE_ID = iter(str(i) for i in range(1, 1000))


def _next_rid() -> str:
    return str(next(_RULE_ID))


def _reset_rid():
    global _RULE_ID
    _RULE_ID = iter(str(i) for i in range(1, 1000))


def _classify_risk(sp_action: str, missing: List[str], target_platform: str) -> str:
    action_clear = sp_action not in ("", "unknown")
    if not action_clear:
        return "fatal"
    fatal_kws = ["action 不明确", "zone 缺失"]
    for m in missing:
        for kw in fatal_kws:
            if kw in m:
                return "fatal"
    if not target_platform:
        if any("安全策略" in m for m in missing):
            return "fatal"
    if missing:
        return "warning"
    return "info"


class SecurityPolicyAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "security_policy"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        _reset_rid()
        lines = config_text.splitlines()
        missing: List[str] = []
        rules: List[Dict[str, Any]] = []
        source_lines: List[str] = []

        vendor_lower = vendor.lower()
        is_huawei = vendor_lower in ("huawei",)
        is_h3c = vendor_lower in ("h3c",)
        is_cisco = vendor_lower in ("cisco",)

        any_found = False

        # ── Huawei security-policy ─────────────────────────────────
        if is_huawei:
            parsed = self._parse_huawei(lines, missing, source_lines)
            if parsed:
                any_found = True
                rules.extend(parsed)

        # ── H3C security-policy ip ─────────────────────────────────
        if is_h3c:
            parsed = self._parse_h3c(lines, missing, source_lines)
            if parsed:
                any_found = True
                rules.extend(parsed)

        # ── Cisco ASA access-list → inferred security policy ───────
        if is_cisco:
            parsed = self._parse_asa(lines, missing, source_lines)
            if parsed:
                any_found = True
                rules.extend(parsed)

        if not any_found:
            return FeatureAnalysis(
                feature="security_policy",
                status="skipped",
                risk_level="info",
                notes=["未发现安全策略配置"],
            )

        for r in rules:
            if not r.get("source_zone"):
                msg = r["rule_id"] + ": 缺少 source-zone，zone 缺失"
                if msg not in missing:
                    missing.append(msg)
            if not r.get("destination_zone"):
                msg = r["rule_id"] + ": 缺少 destination-zone，zone 缺失"
                if msg not in missing:
                    missing.append(msg)

        actions = {r["action"] for r in rules}
        primary_action = actions.pop() if len(actions) == 1 else "mixed"
        risk = _classify_risk(primary_action, missing, platform)
        manual = risk in ("warning", "fatal")

        return FeatureAnalysis(
            feature="security_policy",
            status="analyzed",
            risk_level=risk,
            manual_review_required=manual,
            rules=rules,
            missing_context=missing,
            source_lines=source_lines,
            metadata={"platform_hint": "firewall"},
        )

    # ── Huawei parser ──────────────────────────────────────────────

    def _parse_huawei(self, lines: List[str], missing: List[str], source_lines: List[str]) -> List[Dict]:
        rules: List[Dict] = []
        in_policy = False
        cur: Dict | None = None
        rule_active = False

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            if _HW_POLICY_START.match(stripped):
                in_policy = True
                _pol_indent = len(line) - len(line.lstrip())
                rule_active = False
                cur = None
                continue

            if not in_policy:
                continue

            cur_indent = len(line) - len(line.lstrip())
            if cur_indent <= _pol_indent:
                if cur is not None and rule_active:
                    rules.append(cur)
                    cur = None
                    rule_active = False
                in_policy = False
                continue

            m = _HW_RULE_NAME.match(stripped)
            if m:
                if cur is not None and rule_active:
                    rules.append(cur)
                cur = self._new_rule()
                cur["name"] = m.group(1)
                cur["rule_id"] = _next_rid()
                rule_active = True
                source_lines.append(stripped)
                continue

            if not rule_active or cur is None:
                continue

            m = _HW_SOURCE_ZONE.match(stripped)
            if m:
                cur["source_zone"] = m.group(1)
                cur["references"]["zone"].append(m.group(1))
                source_lines.append(stripped)
                continue
            m = _HW_DEST_ZONE.match(stripped)
            if m:
                cur["destination_zone"] = m.group(1)
                cur["references"]["zone"].append(m.group(1))
                source_lines.append(stripped)
                continue
            m = _HW_SOURCE_ADDR.match(stripped)
            if m:
                addr = m.group(1)
                cur["source"].append(addr)
                cur["references"]["address_object"].append(addr)
                source_lines.append(stripped)
                continue
            m = _HW_DEST_ADDR.match(stripped)
            if m:
                addr = m.group(1)
                cur["destination"].append(addr)
                cur["references"]["address_object"].append(addr)
                source_lines.append(stripped)
                continue
            m = _HW_SOURCE_ADDR_SET.match(stripped)
            if m:
                cur["source"].append(m.group(1))
                cur["references"]["address_object"].append(m.group(1))
                source_lines.append(stripped)
                continue
            m = _HW_DEST_ADDR_SET.match(stripped)
            if m:
                cur["destination"].append(m.group(1))
                cur["references"]["address_object"].append(m.group(1))
                source_lines.append(stripped)
                continue
            m = _HW_SERVICE.match(stripped)
            if m:
                cur["service"].append(m.group(1))
                cur["references"]["service_object"].append(m.group(1))
                source_lines.append(stripped)
                continue
            m = _HW_SERVICE_SET.match(stripped)
            if m:
                cur["service"].append(m.group(1))
                cur["references"]["service_object"].append(m.group(1))
                source_lines.append(stripped)
                continue
            m = _HW_ACTION.match(stripped)
            if m:
                a = m.group(1).lower()
                cur["action"] = "deny" if a == "drop" else a
                source_lines.append(stripped)
                continue
            m = _HW_APPLICATION.match(stripped)
            if m:
                cur["application"].append(m.group(1))
                continue
            m = _HW_USER.match(stripped)
            if m:
                cur["user"].append(m.group(1))
                continue
            m = _HW_TIME_RANGE.match(stripped)
            if m:
                cur["time_range"] = m.group(1)
                continue
            m = _HW_LOG.match(stripped)
            if m:
                cur["log"] = True

        if cur is not None and rule_active:
            rules.append(cur)
        return rules

    # ── H3C parser ────────────────────────────────────────────────

    def _parse_h3c(self, lines: List[str], missing: List[str], source_lines: List[str]) -> List[Dict]:
        rules: List[Dict] = []
        in_policy = False
        cur: Dict | None = None
        rule_active = False

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            if _H3_POLICY_IP.match(stripped):
                in_policy = True
                _pol_indent = len(line) - len(line.lstrip())
                rule_active = False
                cur = None
                continue

            if not in_policy:
                continue

            cur_indent = len(line) - len(line.lstrip())
            if cur_indent <= _pol_indent:
                if cur is not None and rule_active:
                    rules.append(cur)
                    cur = None
                    rule_active = False
                in_policy = False
                continue

            m = _H3_RULE.match(stripped)
            if m:
                if cur is not None and rule_active:
                    rules.append(cur)
                cur = self._new_rule()
                cur["rule_id"] = m.group(1)
                if m.group(2):
                    cur["name"] = m.group(2)
                rule_active = True
                source_lines.append(stripped)
                continue

            if not rule_active or cur is None:
                continue

            m = _H3_SOURCE_ZONE.match(stripped)
            if m:
                cur["source_zone"] = m.group(1)
                cur["references"]["zone"].append(m.group(1))
                source_lines.append(stripped)
                continue
            m = _H3_DEST_ZONE.match(stripped)
            if m:
                cur["destination_zone"] = m.group(1)
                cur["references"]["zone"].append(m.group(1))
                source_lines.append(stripped)
                continue
            m = _H3_SOURCE_IP.match(stripped)
            if m:
                cur["source"].append(m.group(1))
                cur["references"]["address_object"].append(m.group(1))
                source_lines.append(stripped)
                continue
            m = _H3_DEST_IP.match(stripped)
            if m:
                cur["destination"].append(m.group(1))
                cur["references"]["address_object"].append(m.group(1))
                source_lines.append(stripped)
                continue
            m = _H3_SERVICE.match(stripped)
            if m:
                cur["service"].append(m.group(1))
                cur["references"]["service_object"].append(m.group(1))
                source_lines.append(stripped)
                continue
            m = _H3_ACTION.match(stripped)
            if m:
                cur["action"] = "deny" if m.group(1).lower() == "drop" else "permit"
                source_lines.append(stripped)
                continue
            m = _H3_LOG.match(stripped)
            if m:
                cur["log"] = True

        if cur is not None and rule_active:
            rules.append(cur)
        return rules

    # ── Cisco ASA parser ──────────────────────────────────────────

    def _parse_asa(self, lines: List[str], missing: List[str], source_lines: List[str]) -> List[Dict]:
        rules: List[Dict] = []
        acl_groups: Dict[str, Dict] = {}  # acl_name -> {in, out, interface, ...}
        acl_rules: Dict[str, List[Dict]] = {}

        # Phase 1: collect object definitions for resolution
        objects: Dict[str, str] = {}
        current_object = None
        for line in lines:
            stripped = line.strip()
            m = _ASA_OBJECT_NETWORK.match(stripped)
            if m:
                current_object = m.group(1)
                continue
            m = _ASA_OBJECT_GROUP.match(stripped)
            if m:
                current_object = m.group(1)
                continue
            if current_object:
                m = _ASA_HOST.match(stripped)
                if m:
                    objects[current_object] = m.group(1)
                    current_object = None
                    continue
                m = _ASA_SUBNET.match(stripped) or _ASA_NETWORK.match(stripped)
                if m:
                    objects[current_object] = f"{m.group(1)} {m.group(2)}"
                    current_object = None
                    continue

        # Phase 2: collect access-group bindings
        for line in lines:
            stripped = line.strip()
            m = _ASA_ACCESS_GROUP.match(stripped)
            if m:
                acl_groups[m.group(1)] = {
                    "direction": m.group(2),
                    "interface": m.group(3),
                }
                source_lines.append(stripped)

        # Phase 3: parse access-list entries
        for line in lines:
            stripped = line.strip()
            m = _ASA_ACL_LINE.match(stripped)
            if not m:
                continue
            acl_name = m.group(1)
            action = m.group(2).lower()
            proto = m.group(3)
            src_raw = m.group(4).strip()
            dst_raw = m.group(5).strip()

            if proto.lower().startswith("object-group"):
                ref_name = proto.split(None, 1)[-1] if " " in proto else ""
            else:
                ref_name = ""

            def _resolve_addr(raw: str) -> str:
                raw = raw.strip()
                raw = re.sub(r'\s+eq\s+\S+', '', raw, flags=re.IGNORECASE).strip()
                if raw.lower() == "any":
                    return "any"
                if raw.lower().startswith("host "):
                    return raw[5:].strip()
                if raw.lower().startswith("interface "):
                    return raw[10:].strip()
                if raw.lower().startswith("object "):
                    return raw[7:].strip()
                parts = raw.split()
                if len(parts) >= 2:
                    return raw
                return raw

            src = _resolve_addr(src_raw)
            dst = _resolve_addr(dst_raw)

            resolved_src = objects.get(src, src)
            resolved_dst = objects.get(dst, dst)

            eq_match = re.search(r'eq\s+(\S+)', stripped, re.IGNORECASE)
            port_val = eq_match.group(1) if eq_match else ""

            rule: Dict[str, Any] = {
                "rule_id": _next_rid(),
                "name": acl_name,
                "action": action,
                "source_zone": "",
                "destination_zone": "",
                "source": [resolved_src],
                "destination": [resolved_dst],
                "service": [],
                "application": [],
                "user": [],
                "time_range": None,
                "log": False,
                "references": {
                    "address_object": [],
                    "service_object": [],
                    "zone": [],
                },
                "source_lines": [stripped],
            }

            if port_val:
                rule["service"].append(port_val)
            if ref_name:
                missing.append(
                    f"ACL {acl_name}: object-group {ref_name} 引用需人工核查"
                )

            if acl_name in acl_groups:
                bind = acl_groups[acl_name]
                rule["source_zone"] = bind["interface"]
                rule["references"]["zone"].append(bind["interface"])
                if bind["direction"] == "in":
                    rule["destination_zone"] = "any"
                else:
                    rule["source_zone"] = "any"
                    rule["destination_zone"] = bind["interface"]

            if not rule["source_zone"] and not rule["destination_zone"]:
                missing.append(f"ACL {acl_name}: 缺少 access-group 绑定，无法确定方向")

            source_lines.append(stripped)
            rules.append(rule)

        if rules:
            missing.append("Cisco ACL 推断的安全策略缺少 zone 模型，建议人工校验")

        return rules

    @staticmethod
    def _new_rule() -> Dict:
        return {
            "rule_id": "",
            "name": "",
            "action": "unknown",
            "source_zone": "",
            "destination_zone": "",
            "source": [],
            "destination": [],
            "service": [],
            "application": [],
            "user": [],
            "time_range": None,
            "log": False,
            "references": {
                "address_object": [],
                "service_object": [],
                "zone": [],
            },
            "source_lines": [],
        }
