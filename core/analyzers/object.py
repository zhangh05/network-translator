from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer


# ── Huawei/H3C address-set / service-set ─────────────────────────
_RE_HW_ADDR_SET = re.compile(
    r"^\s*(?:ip\s+)?address-set\s+(\S+)", re.IGNORECASE,
)
_RE_HW_ADDR_MEMBER = re.compile(
    r"^\s*address\s+", re.IGNORECASE,
)
_RE_HW_ADDR_IP = re.compile(
    r"^\s*address\s+(\S+)\s+(\S+)", re.IGNORECASE,
)
_RE_HW_SVC_SET = re.compile(
    r"^\s*(?:ip\s+)?service-set\s+(\S+)", re.IGNORECASE,
)
_RE_HW_SVC_MEMBER = re.compile(
    r"^\s*service\s+", re.IGNORECASE,
)
_RE_HW_SVC_DEF = re.compile(
    r"^\s*service\s+(\S+)\s+(.+)", re.IGNORECASE,
)

# ── Cisco ASA object ──────────────────────────────────────────────
_RE_ASA_OBJECT_NET = re.compile(
    r"^\s*object\s+network\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_SUBNET = re.compile(
    r"^\s*subnet\s+(\S+)\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_HOST = re.compile(
    r"^\s*host\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_RANGE = re.compile(
    r"^\s*range\s+(\S+)\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_NAT = re.compile(
    r"^\s*nat\s+", re.IGNORECASE,
)
_RE_ASA_OBJECT_SVC = re.compile(
    r"^\s*object\s+service\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_SVC_DEF = re.compile(
    r"^\s*service\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", re.IGNORECASE,
)

# ── Cisco ASA object-group ────────────────────────────────────────
_RE_ASA_OG_NET = re.compile(
    r"^\s*object-group\s+network\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_OG_NET_OBJECT = re.compile(
    r"^\s*network-object\s+object\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_OG_NET_SUBNET = re.compile(
    r"^\s*network-object\s+(\S+)\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_OG_NET_HOST = re.compile(
    r"^\s*network-object\s+host\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_OG_SVC = re.compile(
    r"^\s*object-group\s+service\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_OG_SVC_OBJECT = re.compile(
    r"^\s*service-object\s+object\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_OG_SVC_DEF = re.compile(
    r"^\s*service-object\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", re.IGNORECASE,
)

_HW_VENDORS = {"huawei", "h3c"}
_ASA_VENDORS = {"cisco"}


def _normalize_ip(m: str) -> str:
    if m.count(".") == 3 and m != "0.0.0.0":
        return m + "/32" if "/" not in m else m
    return m


class ObjectAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "address_object"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        lines = config_text.splitlines()
        vendor_lower = vendor.lower()
        is_hw = vendor_lower in _HW_VENDORS
        is_asa = vendor_lower in _ASA_VENDORS

        if not is_hw and not is_asa:
            return FeatureAnalysis(
                feature="address_object", status="skipped", risk_level="info",
                notes=[f"Vendor {vendor} not supported"],
            )

        any_obj = any(
            "address-set" in l.lower() or "service-set" in l.lower()
            or "object-group" in l.lower() or "object network" in l.lower()
            or "object service" in l.lower()
            or "network-object" in l.lower() or "service-object" in l.lower()
            for l in lines
        )
        if not any_obj:
            return FeatureAnalysis(
                feature="address_object", status="skipped", risk_level="info",
                notes=["未发现对象定义"],
            )

        addr_objects: Dict[str, Dict] = {}
        svc_objects: Dict[str, Dict] = {}
        missing: List[str] = []
        refs: Dict[str, List[str]] = {"address_object": [], "service_object": []}

        if is_hw:
            self._parse_hw(lines, addr_objects, svc_objects, refs)
        if is_asa:
            self._parse_asa(lines, addr_objects, svc_objects, refs)

        if not addr_objects and not svc_objects:
            return FeatureAnalysis(
                feature="address_object", status="skipped", risk_level="info",
                notes=["包含对象关键词但未识别到有效定义"],
            )

        self._cross_ref(addr_objects, svc_objects, refs, missing)

        rules = []
        for name, obj in addr_objects.items():
            rules.append(obj)
        for name, obj in svc_objects.items():
            rules.append(obj)

        has_fatal = any("fatal" in m for m in missing)
        risk = "info"
        if missing:
            risk = "warning"
        if has_fatal:
            risk = "fatal"

        return FeatureAnalysis(
            feature="address_object",
            status="analyzed",
            risk_level=risk,
            manual_review_required=risk in ("warning", "fatal"),
            rules=rules,
            references=refs,
            missing_context=missing,
            source_lines=[],
            notes=[],
        )

    def _parse_hw(self, lines, addr_objects, svc_objects, refs):
        current_addr_set: Optional[str] = None
        current_svc_set: Optional[str] = None
        addr_indent = 0
        svc_indent = 0

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue
            indent = len(raw) - len(raw.lstrip())

            m = _RE_HW_ADDR_SET.match(stripped)
            if m:
                current_addr_set = m.group(1)
                current_svc_set = None
                addr_indent = indent
                addr_objects[current_addr_set] = {
                    "object_type": "address",
                    "name": current_addr_set,
                    "members": [], "services": [],
                    "references": {}, "source_lines": [],
                }
                refs["address_object"].append(current_addr_set)
                continue

            m = _RE_HW_SVC_SET.match(stripped)
            if m:
                current_svc_set = m.group(1)
                current_addr_set = None
                svc_indent = indent
                svc_objects[current_svc_set] = {
                    "object_type": "service",
                    "name": current_svc_set,
                    "members": [], "services": [],
                    "references": {}, "source_lines": [],
                }
                refs["service_object"].append(current_svc_set)
                continue

            if current_addr_set:
                if indent > addr_indent and _RE_HW_ADDR_MEMBER.match(stripped):
                    mm = _RE_HW_ADDR_IP.match(stripped)
                    if mm:
                        a = mm.group(1)
                        b = mm.group(2)
                        if a and b:
                            addr_objects[current_addr_set]["members"].append(f"{a}/{b}")
                        elif a:
                            addr_objects[current_addr_set]["members"].append(_normalize_ip(a))
                    continue
                if indent <= addr_indent and stripped[0].isalpha() and not stripped.startswith("address"):
                    current_addr_set = None
                continue

            if current_svc_set:
                if indent > svc_indent and _RE_HW_SVC_MEMBER.match(stripped):
                    mm = _RE_HW_SVC_DEF.match(stripped)
                    if mm:
                        proto = mm.group(1)
                        spec = mm.group(2).strip()
                        svc_objects[current_svc_set]["services"].append({
                            "protocol": proto, "spec": spec,
                        })
                    continue
                if indent <= svc_indent and stripped[0].isalpha() and not stripped.startswith("service"):
                    current_svc_set = None
                continue

    def _parse_asa(self, lines, addr_objects, svc_objects, refs):
        current_obj_net: Optional[str] = None
        current_obj_svc: Optional[str] = None
        current_og_net: Optional[str] = None
        current_og_svc: Optional[str] = None
        obj_indent = 0
        og_indent = 0

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue
            indent = len(raw) - len(raw.lstrip())

            m = _RE_ASA_OBJECT_NET.match(stripped)
            if m:
                self._flush_asa(current_obj_net, current_obj_svc, current_og_net, current_og_svc)
                name = m.group(1)
                current_obj_net = name
                current_obj_svc = current_og_net = current_og_svc = None
                obj_indent = indent
                addr_objects[name] = {
                    "object_type": "address",
                    "name": name, "members": [], "services": [],
                    "references": {}, "source_lines": [],
                }
                refs["address_object"].append(name)
                continue

            m = _RE_ASA_OBJECT_SVC.match(stripped)
            if m:
                self._flush_asa(current_obj_net, current_obj_svc, current_og_net, current_og_svc)
                name = m.group(1)
                current_obj_svc = name
                current_obj_net = current_og_net = current_og_svc = None
                obj_indent = indent
                svc_objects[name] = {
                    "object_type": "service",
                    "name": name, "members": [], "services": [],
                    "references": {}, "source_lines": [],
                }
                refs["service_object"].append(name)
                continue

            m = _RE_ASA_OG_NET.match(stripped)
            if m:
                self._flush_asa(current_obj_net, current_obj_svc, current_og_net, current_og_svc)
                name = m.group(1)
                current_og_net = name
                current_og_svc = current_obj_net = current_obj_svc = None
                og_indent = indent
                addr_objects[name] = {
                    "object_type": "network_group",
                    "name": name, "members": [], "services": [],
                    "references": {}, "source_lines": [],
                }
                refs["address_object"].append(name)
                continue

            m = _RE_ASA_OG_SVC.match(stripped)
            if m:
                self._flush_asa(current_obj_net, current_obj_svc, current_og_net, current_og_svc)
                name = m.group(1)
                current_og_svc = name
                current_og_net = current_obj_net = current_obj_svc = None
                og_indent = indent
                svc_objects[name] = {
                    "object_type": "service_group",
                    "name": name, "members": [], "services": [],
                    "references": {}, "source_lines": [],
                }
                refs["service_object"].append(name)
                continue

            # ── sub-commands ──
            if current_obj_net:
                mm = _RE_ASA_SUBNET.match(stripped)
                if mm:
                    addr_objects[current_obj_net]["members"].append(f"{mm.group(1)}/{mm.group(2)}")
                    continue
                mm = _RE_ASA_HOST.match(stripped)
                if mm:
                    addr_objects[current_obj_net]["members"].append(_normalize_ip(mm.group(1)))
                    continue
                mm = _RE_ASA_RANGE.match(stripped)
                if mm:
                    addr_objects[current_obj_net]["members"].append(f"{mm.group(1)}-{mm.group(2)}")
                    continue
                mm = _RE_ASA_NAT.match(stripped)
                if mm:
                    continue
                if indent <= obj_indent and stripped[0].isalpha():
                    current_obj_net = None
                continue

            if current_obj_svc:
                mm = _RE_ASA_SVC_DEF.match(stripped)
                if mm:
                    svc_objects[current_obj_svc]["services"].append({
                        "protocol": mm.group(1),
                        "source": f"{mm.group(2)} {mm.group(3)}",
                        "destination": mm.group(4),
                    })
                    continue
                if indent <= obj_indent and stripped[0].isalpha():
                    current_obj_svc = None
                continue

            if current_og_net:
                mm = _RE_ASA_OG_NET_OBJECT.match(stripped)
                if mm:
                    obj_name = mm.group(1)
                    addr_objects[current_og_net]["members"].append(f"object:{obj_name}")
                    addr_objects[current_og_net].setdefault("references", {}).setdefault("ref_objects", []).append(obj_name)
                    continue
                mm = _RE_ASA_OG_NET_HOST.match(stripped)
                if mm:
                    addr_objects[current_og_net]["members"].append(_normalize_ip(mm.group(1)))
                    continue
                mm = _RE_ASA_OG_NET_SUBNET.match(stripped)
                if mm:
                    addr_objects[current_og_net]["members"].append(f"{mm.group(1)}/{mm.group(2)}")
                    continue
                if indent <= og_indent and stripped[0].isalpha():
                    current_og_net = None
                continue

            if current_og_svc:
                mm = _RE_ASA_OG_SVC_OBJECT.match(stripped)
                if mm:
                    obj_name = mm.group(1)
                    svc_objects[current_og_svc]["services"].append({"type": "ref", "object": obj_name})
                    svc_objects[current_og_svc].setdefault("references", {}).setdefault("ref_objects", []).append(obj_name)
                    continue
                mm = _RE_ASA_OG_SVC_DEF.match(stripped)
                if mm:
                    svc_objects[current_og_svc]["services"].append({
                        "protocol": mm.group(1),
                        "source": f"{mm.group(2)} {mm.group(3)}",
                        "destination": mm.group(4),
                    })
                    continue
                if indent <= og_indent and stripped[0].isalpha():
                    current_og_svc = None
                continue

    @staticmethod
    def _flush_asa(*args):
        pass

    @staticmethod
    def _cross_ref(addr_objects, svc_objects, refs, missing):
        all_addr_names = set(addr_objects.keys())
        all_svc_names = set(svc_objects.keys())

        for name, obj in addr_objects.items():
            for ref_obj in obj.get("references", {}).get("ref_objects", []):
                if ref_obj not in all_addr_names:
                    missing.append(
                        f"object-group {name} 引用了未定义的 address object {ref_obj}——warning"
                    )

        for name, obj in svc_objects.items():
            for ref_obj in obj.get("references", {}).get("ref_objects", []):
                if ref_obj not in all_svc_names:
                    missing.append(
                        f"object-group {name} 引用了未定义的 service object {ref_obj}——warning"
                    )

        # circular reference detection: follow object refs
        visited = set()

        def _find_cycle(graph, node, path):
            if node in path:
                cycle = path[path.index(node):] + [node]
                missing.append(
                    f"object-group {node} 存在循环引用 {'→'.join(cycle)}——fatal"
                )
                return True
            if node in visited:
                return False
            visited.add(node)
            path.append(node)
            for member in graph.get(node, {}).get("members", []):
                if member.startswith("object:"):
                    ref_name = member.split(":", 1)[1]
                    if ref_name in graph:
                        if _find_cycle(graph, ref_name, path):
                            path.pop()
                            return True
            path.pop()
            return False

        for name in list(addr_objects.keys()):
            _find_cycle(addr_objects, name, [])
