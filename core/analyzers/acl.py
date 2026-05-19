from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer

# ── Cisco standard / extended numbered ACL ────────────────────────────────────
_CISCO_STD_ACL = re.compile(
    r"^\s*access-list\s+(\d+)\s+(permit|deny)\s+(.+)",
    re.IGNORECASE,
)
_CISCO_EXT_ACL = re.compile(
    r"^\s*access-list\s+(\d+)\s+(permit|deny)\s+"
    r"(\S+)\s+(.+?)\s+(.+)",
    re.IGNORECASE,
)

# ── Cisco named ACL ──────────────────────────────────────────────────────────
_CISCO_NAMED_ACL = re.compile(
    r"^\s*ip\s+access-list\s+(extended|standard)\s+(\S+)",
    re.IGNORECASE,
)
_CISCO_NAMED_ENTRY = re.compile(
    r"^\s*(permit|deny)\s+(\S+)\s+(.+?)\s+(.+)",
    re.IGNORECASE,
)

# ── Huawei / H3C acl ─────────────────────────────────────────────────────────
_HW_ACL_NUM = re.compile(r"^\s*acl\s+(?:number\s+)?(\S+)", re.IGNORECASE)
_HW_ACL_NAME = re.compile(r"^\s*acl\s+name\s+(\S+)", re.IGNORECASE)
_HW_RULE = re.compile(
    r"^\s*rule\s+(\S+)\s+(permit|deny)\s+(\S+)(.*)",
    re.IGNORECASE,
)

# ── Object / set references ──────────────────────────────────────────────────
_RE_OBJECT = re.compile(r"object-group\s+(\S+)", re.IGNORECASE)
_RE_ADDR_SET = re.compile(r"address-set\s+(\S+)", re.IGNORECASE)
_RE_SVC_SET = re.compile(r"service-set\s+(\S+)", re.IGNORECASE)

_KNOWN_PROTOS = {"ip", "tcp", "udp", "icmp", "gre", "esp", "ah", "igmp", "vrrp", "ospf", "pim", "rsvp"}

_RULE_ID = iter(str(i) for i in range(1, 1000))


def _next_rid() -> str:
    return str(next(_RULE_ID))


def _reset_rid():
    global _RULE_ID
    _RULE_ID = iter(str(i) for i in range(1, 1000))


def _normalize_proto(raw: str) -> str:
    r = raw.strip().lower()
    return r if r in _KNOWN_PROTOS else "unknown"


def _classify_risk(action: str, missing: List[str]) -> str:
    if not action or action == "unknown":
        return "fatal"
    for m in missing:
        if "无法归属" in m or "结构破碎" in m:
            return "fatal"
    if missing:
        return "warning"
    return "info"


class AclAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "acl"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        _reset_rid()
        lines = config_text.splitlines()
        missing: List[str] = []
        rules: List[Dict[str, Any]] = []
        source_lines: List[str] = []
        collected_ids: List[str] = []
        collected_names: List[str] = []
        any_found = False

        vendor_lower = vendor.lower()
        is_cisco = vendor_lower == "cisco"
        is_hw_h3c = vendor_lower in ("huawei", "h3c")

        # Phase 1: collect object definitions (Cisco)
        objects: Dict[str, str] = {}
        current_object = None
        for line in lines:
            stripped = line.strip()
            m = re.match(r"^\s*object-group\s+\S+\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                current_object = m.group(1)
                continue
            m = re.match(r"^\s*object\s+network\s+(\S+)", stripped, re.IGNORECASE)
            if m:
                current_object = m.group(1)
                continue
            if current_object:
                m = re.match(r"^\s*(?:host|network|subnet)\s+(\S+)", stripped, re.IGNORECASE)
                if m:
                    objects[current_object] = m.group(1)
                    current_object = None
                    continue

        # ── Cisco numbered ACL ────────────────────────────────────
        if is_cisco:
            for line in lines:
                stripped = line.strip()
                m = _CISCO_EXT_ACL.match(stripped)
                if m:
                    any_found = True
                    num = m.group(1)
                    action = m.group(2).lower()
                    proto = _normalize_proto(m.group(3))
                    src_raw = m.group(4).strip()
                    dst_raw = m.group(5).strip()
                    eq_match = re.search(r"eq\s+(\S+)", stripped, re.IGNORECASE)
                    dport = eq_match.group(1) if eq_match else ""

                    refs: Dict[str, List[str]] = {"object_group": [], "address_object": [], "service_object": []}
                    for ref in _RE_OBJECT.findall(stripped):
                        refs["object_group"].append(ref)
                    for ref in _RE_ADDR_SET.findall(stripped):
                        refs["address_object"].append(ref)

                    src = self._resolve_cisco_addr(src_raw, objects)
                    dst = self._resolve_cisco_addr(dst_raw, objects)

                    if num not in collected_ids:
                        collected_ids.append(num)

                    rules.append({
                        "acl_id": num,
                        "acl_name": None,
                        "rule_id": _next_rid(),
                        "action": action,
                        "protocol": proto,
                        "source": src,
                        "destination": dst,
                        "source_port": None,
                        "destination_port": dport or None,
                        "direction": None,
                        "references": refs,
                        "source_lines": [stripped],
                    })
                    source_lines.append(stripped)
                    continue

                m = _CISCO_STD_ACL.match(stripped)
                if m:
                    any_found = True
                    num = m.group(1)
                    action = m.group(2).lower()
                    rest = m.group(3).strip()
                    src = self._resolve_cisco_addr(rest, objects)
                    if num not in collected_ids:
                        collected_ids.append(num)
                    rules.append({
                        "acl_id": num,
                        "acl_name": None,
                        "rule_id": _next_rid(),
                        "action": action,
                        "protocol": "ip",
                        "source": src,
                        "destination": "any",
                        "source_port": None,
                        "destination_port": None,
                        "direction": None,
                        "references": {"object_group": [], "address_object": [], "service_object": []},
                        "source_lines": [stripped],
                    })
                    source_lines.append(stripped)

            # ── Cisco named ACL ──────────────────────────────────
            named_sections = self._parse_cisco_named_acl(lines, objects)
            for section in named_sections:
                any_found = True
                collected_names.append(section["acl_name"])
                for entry in section["entries"]:
                    rules.append(entry)
                    source_lines.extend(entry.get("source_lines", []))

        # ── Huawei / H3C acl ─────────────────────────────────────
        if is_hw_h3c:
            sections = self._parse_hw_acl(lines)
            for section in sections:
                any_found = True
                acl_id = section["acl_id"]
                if acl_id not in collected_ids:
                    collected_ids.append(acl_id)
                acl_name = section.get("acl_name")
                if acl_name and acl_name not in collected_names:
                    collected_names.append(acl_name)
                for entry in section["entries"]:
                    rules.append(entry)
                    source_lines.extend(entry.get("source_lines", []))

                for ref in [*_RE_OBJECT.findall(section.get("raw", "")),
                            *_RE_ADDR_SET.findall(section.get("raw", "")),
                            *_RE_SVC_SET.findall(section.get("raw", ""))]:
                    if not any(ref in r["references"]["object_group"]
                               + r["references"]["address_object"]
                               + r["references"]["service_object"]
                               for r in rules[-len(section["entries"]):]):
                        pass

        if not any_found:
            return FeatureAnalysis(
                feature="acl",
                status="skipped",
                risk_level="info",
                notes=["未发现 ACL 配置"],
            )

        risk = _classify_risk("permit" if rules else "", missing)

        return FeatureAnalysis(
            feature="acl",
            status="analyzed",
            risk_level=risk,
            manual_review_required=risk in ("warning", "fatal"),
            rules=rules,
            missing_context=missing,
            source_lines=list(dict.fromkeys(source_lines)),
            metadata={"acl_ids": collected_ids, "acl_names": collected_names},
        )

    # ── Cisco addr resolver ───────────────────────────────────────

    @staticmethod
    def _resolve_cisco_addr(raw: str, objects: Dict[str, str]) -> str:
        raw = raw.strip()
        raw = re.sub(r"\s+eq\s+\S+", "", raw, flags=re.IGNORECASE).strip()
        if raw.lower() == "any":
            return "any"
        if raw.lower().startswith("host "):
            return raw[5:].strip()
        if raw.lower().startswith("interface "):
            return raw[10:].strip()
        if raw.lower().startswith("object "):
            return raw[7:].strip()
        if raw in objects:
            return objects[raw]
        parts = raw.split()
        if len(parts) == 2:
            return f"{parts[0]} {parts[1]}"
        return raw

    # ── Cisco named ACL parser ────────────────────────────────────

    @staticmethod
    def _parse_cisco_named_acl(lines: List[str], objects: Dict[str, str]) -> List[Dict]:
        sections: List[Dict] = []
        current_name = None
        current_type = None
        current_entries: List[Dict] = []
        policy_indent = 0

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            m = _CISCO_NAMED_ACL.match(stripped)
            if m:
                if current_name and current_entries:
                    sections.append({"acl_name": current_name, "acl_type": current_type, "entries": current_entries})
                current_name = m.group(2)
                current_type = m.group(1).lower()
                current_entries = []
                policy_indent = len(line) - len(line.lstrip())
                continue

            if current_name is None:
                continue

            cur_indent = len(line) - len(line.lstrip())
            if cur_indent <= policy_indent and not stripped.startswith(("permit", "deny")):
                if current_entries:
                    sections.append({"acl_name": current_name, "acl_type": current_type, "entries": current_entries})
                current_name = None
                current_entries = []
                continue

            m2 = _CISCO_NAMED_ENTRY.match(stripped)
            if m2:
                action = m2.group(1).lower()
                proto = _normalize_proto(m2.group(2))
                src_raw = m2.group(3).strip()
                dst_raw = m2.group(4).strip()
                eq_match = re.search(r"eq\s+(\S+)", stripped, re.IGNORECASE)
                dport = eq_match.group(1) if eq_match else ""

                src = AclAnalyzer._resolve_cisco_addr(src_raw, objects)
                dst = AclAnalyzer._resolve_cisco_addr(dst_raw, objects)

                current_entries.append({
                    "acl_id": current_name,
                    "acl_name": current_name,
                    "rule_id": _next_rid(),
                    "action": action,
                    "protocol": proto,
                    "source": src,
                    "destination": dst,
                    "source_port": None,
                    "destination_port": dport or None,
                    "direction": None,
                    "references": {"object_group": [], "address_object": [], "service_object": []},
                    "source_lines": [stripped],
                })

        if current_name and current_entries:
            sections.append({"acl_name": current_name, "acl_type": current_type, "entries": current_entries})
        return sections

    # ── Huawei / H3C ACL parser ───────────────────────────────────

    @staticmethod
    def _parse_hw_acl(lines: List[str]) -> List[Dict]:
        """
        解析 Huawei/H3C ACL 段:

        acl number 3000
         rule 5 permit ip source 10.0.0.0 0.0.0.255 destination any
         rule 10 deny tcp source any destination 1.1.1.1 0 destination-port eq 22
        """
        sections: List[Dict] = []
        current_id = None
        current_name = None
        current_entries: List[Dict] = []
        acl_indent = 0
        in_acl = False

        # Important: process line by line, using raw line for indentation
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            m = _HW_ACL_NAME.match(stripped)
            if m:
                current_name = m.group(1)
                current_id = current_name
                current_entries = []
                acl_indent = len(line) - len(line.lstrip())
                in_acl = True
                continue

            m = _HW_ACL_NUM.match(stripped)
            if m:
                if in_acl and current_entries:
                    sections.append({
                        "acl_id": current_id,
                        "acl_name": current_name,
                        "entries": current_entries,
                        "raw": stripped,
                    })
                acl_id = m.group(1)
                if acl_id.lower() in ("name",):
                    continue
                current_id = acl_id
                current_name = None
                current_entries = []
                acl_indent = len(line) - len(line.lstrip())
                in_acl = True
                continue

            if not in_acl:
                continue

            cur_indent = len(line) - len(line.lstrip())
            if cur_indent <= acl_indent and not stripped.startswith("rule"):
                if current_entries:
                    sections.append({
                        "acl_id": current_id,
                        "acl_name": current_name,
                        "entries": current_entries,
                        "raw": stripped,
                    })
                in_acl = False
                current_entries = []
                continue

            m2 = _HW_RULE.match(stripped)
            if m2:
                rule_num = m2.group(1)
                action = m2.group(2).lower()
                proto = _normalize_proto(m2.group(3))
                rest = m2.group(4).strip()

                parsed = AclAnalyzer._parse_hw_rule_body(rest)
                eq_match = re.search(r"(?:destination-port|dest-port)\s+eq\s+(\S+)", rest, re.IGNORECASE)
                dport = eq_match.group(1) if eq_match else ""
                seq_match = re.search(r"(?:source-port|src-port)\s+eq\s+(\S+)", rest, re.IGNORECASE)
                sport = seq_match.group(1) if seq_match else ""

                current_entries.append({
                    "acl_id": current_id,
                    "acl_name": current_name,
                    "rule_id": rule_num,
                    "action": action,
                    "protocol": proto,
                    "source": parsed.get("source", "any"),
                    "destination": parsed.get("destination", "any"),
                    "source_port": sport or None,
                    "destination_port": dport or None,
                    "direction": None,
                    "references": {"object_group": [], "address_object": [], "service_object": []},
                    "source_lines": [stripped],
                })

        if in_acl and current_entries:
            sections.append({
                "acl_id": current_id,
                "acl_name": current_name,
                "entries": current_entries,
                "raw": "",
            })
        return sections

    @staticmethod
    def _parse_hw_rule_body(rest: str) -> Dict[str, str]:
        """Extract source/destination from Huawei rule body."""
        result: Dict[str, str] = {}

        # Match source block
        src_m = re.search(
            r"source\s+(\S+)(?:\s+(\S+))?(?=\s+destination|\s+\w+[-]?\w+|\s*$)",
            rest,
            re.IGNORECASE,
        )
        if src_m:
            addr = src_m.group(1)
            mask = src_m.group(2)
            if addr.lower() == "any":
                result["source"] = "any"
            elif mask:
                result["source"] = f"{addr}/{mask}"
            else:
                result["source"] = addr
        else:
            result["source"] = "any"

        # Match destination block
        dst_m = re.search(
            r"destination\s+(\S+)(?:\s+(\S+))?(?=\s+\w+[-]?\w+\s+\w+|\s*$)",
            rest,
            re.IGNORECASE,
        )
        if dst_m:
            addr = dst_m.group(1)
            mask = dst_m.group(2)
            if addr.lower() == "any":
                result["destination"] = "any"
            elif mask:
                result["destination"] = f"{addr}/{mask}"
            else:
                result["destination"] = addr
        else:
            result["destination"] = "any"

        return result
