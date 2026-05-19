from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer


# ── Huawei/H3C classifer, behavior, policy ──────────────────────────────────────
_RE_HW_CLASSIFIER = re.compile(
    r"^\s*traffic\s+classifier\s+(\S+)", re.IGNORECASE,
)
_RE_HW_BEHAVIOR = re.compile(
    r"^\s*traffic\s+behavior\s+(\S+)", re.IGNORECASE,
)
_RE_HW_POLICY = re.compile(
    r"^\s*traffic\s+policy\s+(\S+)", re.IGNORECASE,
)
_RE_HW_CLASSIFIER_BEHAVIOR = re.compile(
    r"^\s*classifier\s+(\S+)\s+behavior\s+(\S+)", re.IGNORECASE,
)
_RE_HW_INTERFACE_POLICY = re.compile(
    r"^\s*traffic-policy\s+(\S+)\s+(inbound|outbound)",
    re.IGNORECASE,
)

# Huawei/H3C if-match inside classifier
_RE_HW_IF_MATCH_ACL = re.compile(
    r"^\s*if-match\s+acl\s+(\S+)", re.IGNORECASE,
)
_RE_HW_IF_MATCH_PREFIX = re.compile(
    r"^\s*if-match\s+ip-prefix\s+(\S+)", re.IGNORECASE,
)
_RE_HW_IF_MATCH_DSCP = re.compile(
    r"^\s*if-match\s+dscp\s+(\S+)", re.IGNORECASE,
)
_RE_HW_IF_MATCH_PROTO = re.compile(
    r"^\s*if-match\s+protocol\s+(\S+)", re.IGNORECASE,
)

# Huawei/H3C actions inside behavior
_RE_HW_CAR = re.compile(
    r"^\s*car\s+cir\s+(\S+)", re.IGNORECASE,
)
_RE_HW_REMARK_DSCP = re.compile(
    r"^\s*remark\s+dscp\s+(\S+)", re.IGNORECASE,
)
_RE_HW_QUEUE = re.compile(
    r"^\s*queue\s+(\S+)", re.IGNORECASE,
)
_RE_HW_PRIORITY = re.compile(
    r"^\s*priority\s+(\S+)", re.IGNORECASE,
)
_RE_HW_REDIRECT = re.compile(
    r"^\s*redirect", re.IGNORECASE,
)

# ── Cisco class-map / policy-map ────────────────────────────────────────────────
_RE_CISCO_CLASS_MAP = re.compile(
    r"^\s*class-map\s+(?:match-all|match-any)?\s*(\S+)", re.IGNORECASE,
)
_RE_CISCO_POLICY_MAP = re.compile(
    r"^\s*policy-map\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_CLASS = re.compile(
    r"^\s*class\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_SERVICE_POLICY = re.compile(
    r"^\s*service-policy\s+(input|output)\s+(\S+)", re.IGNORECASE,
)

# Cisco match
_RE_CISCO_MATCH_ACCESS = re.compile(
    r"^\s*match\s+(?:access-group|access)\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_MATCH_DSCP = re.compile(
    r"^\s*match\s+(?:ip\s+)?dscp\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_MATCH_PROTO = re.compile(
    r"^\s*match\s+protocol\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_MATCH_PRECEDENCE = re.compile(
    r"^\s*match\s+(?:ip\s+)?precedence\s+(\S+)", re.IGNORECASE,
)

# Cisco actions inside policy class
_RE_CISCO_POLICE = re.compile(
    r"^\s*police\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_SHAPE = re.compile(
    r"^\s*shape\s+(?:average\s+)?(\S+)", re.IGNORECASE,
)
_RE_CISCO_BANDWIDTH = re.compile(
    r"^\s*bandwidth\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_PRIORITY = re.compile(
    r"^\s*priority\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_SET_DSCP = re.compile(
    r"^\s*set\s+(?:ip\s+)?dscp\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_SET_PREC = re.compile(
    r"^\s*set\s+(?:ip\s+)?precedence\s+(\S+)", re.IGNORECASE,
)

# Interface detection (both vendors)
_RE_INTERFACE = re.compile(
    r"^\s*interface\s+(\S+)", re.IGNORECASE,
)

# ── Vendor sets ────────────────────────────────────────────────────────────────
_HW_VENDORS = {"huawei", "h3c"}
_CISCO_VENDORS = {"cisco"}


class QosAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "qos"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        lines = config_text.splitlines()
        vendor_lower = vendor.lower()
        is_hw = vendor_lower in _HW_VENDORS
        is_cisco = vendor_lower in _CISCO_VENDORS

        if not is_hw and not is_cisco:
            return FeatureAnalysis(
                feature="qos", status="skipped", risk_level="info",
                notes=[f"Vendor {vendor} not supported for QoS analysis"],
            )

        # Quick scan
        any_qos = any(
            "classifier" in l.lower() or "behavior" in l.lower()
            or "traffic policy" in l.lower() or "traffic-policy" in l.lower()
            or "class-map" in l.lower() or "policy-map" in l.lower()
            or "service-policy" in l.lower()
            for l in lines
        )
        if not any_qos:
            return FeatureAnalysis(
                feature="qos", status="skipped", risk_level="info",
                notes=["未发现 QoS 配置"],
            )

        # ── Phase 1: collect definitions ──
        classifiers: Dict[str, Dict] = {}
        behaviors: Dict[str, Dict] = {}
        policies: Dict[str, Dict] = {}
        class_maps: Dict[str, Dict] = {}
        policy_maps: Dict[str, Dict] = {}
        interface_bindings: List[Dict] = []

        if is_hw:
            self._parse_hw_qos(lines, classifiers, behaviors, policies, interface_bindings)
        if is_cisco:
            self._parse_cisco_qos(lines, class_maps, policy_maps, interface_bindings)

        if not classifiers and not behaviors and not policies and not class_maps and not policy_maps:
            return FeatureAnalysis(
                feature="qos", status="skipped", risk_level="info",
                notes=["包含 QoS 关键词但未识别到完整策略结构"],
            )

        # ── Phase 2: cross-reference & risk ──
        missing: List[str] = []
        rules: List[Dict] = []
        source_lines: List[str] = []
        refs: Dict[str, List[str]] = {
            "classifier": [], "behavior": [], "policy": [],
            "acl": [], "ip_prefix": [],
        }

        if is_hw:
            self._build_hw_rules(classifiers, behaviors, policies, interface_bindings,
                                  rules, missing, source_lines, refs)
        if is_cisco:
            self._build_cisco_rules(class_maps, policy_maps, interface_bindings,
                                     rules, missing, source_lines, refs)

        # ── Phase 3: risk ──
        has_fatal = any("fatal" in m for m in missing)
        risk = "info"
        if missing:
            risk = "warning"
        if has_fatal:
            risk = "fatal"

        return FeatureAnalysis(
            feature="qos",
            status="analyzed",
            risk_level=risk,
            manual_review_required=risk in ("warning", "fatal"),
            rules=rules,
            references=refs,
            missing_context=missing,
            source_lines=list(dict.fromkeys(source_lines)),
            metadata={
                "classifier_count": len(classifiers) + len(class_maps),
                "policy_count": len(policies) + len(policy_maps),
            },
        )

    # ═══════════════════════════════════════════════════════════════════
    # Huawei/H3C parser
    # ═══════════════════════════════════════════════════════════════════

    def _parse_hw_qos(self, lines, classifiers, behaviors, policies,
                      interface_bindings):
        in_classifier: Optional[str] = None
        in_behavior: Optional[str] = None
        in_policy: Optional[str] = None
        classifier_indent = behavior_indent = policy_indent = 0
        current_interface: Optional[str] = None

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue
            indent = len(raw) - len(raw.lstrip())

            # ── traffic classifier ──
            m = _RE_HW_CLASSIFIER.match(stripped)
            if m:
                self._flush_hw(in_classifier, in_behavior, in_policy)
                in_classifier = m.group(1)
                classifiers[in_classifier] = {
                    "name": in_classifier, "if_matches": [],
                }
                in_behavior = in_policy = None
                classifier_indent = indent
                continue

            # ── traffic behavior ──
            m = _RE_HW_BEHAVIOR.match(stripped)
            if m:
                self._flush_hw(in_classifier, in_behavior, in_policy)
                in_behavior = m.group(1)
                behaviors[in_behavior] = {
                    "name": in_behavior, "actions": [],
                }
                in_classifier = in_policy = None
                behavior_indent = indent
                continue

            # ── traffic policy ──
            m = _RE_HW_POLICY.match(stripped)
            if m:
                self._flush_hw(in_classifier, in_behavior, in_policy)
                in_policy = m.group(1)
                policies[in_policy] = {
                    "name": in_policy, "class_behaviors": [],
                }
                in_classifier = in_behavior = None
                policy_indent = indent
                continue

            # ── interface tracking for binding ──
            m = _RE_INTERFACE.match(stripped)
            if m:
                self._flush_hw(in_classifier, in_behavior, in_policy)
                current_interface = m.group(1)
                in_classifier = in_behavior = in_policy = None
                continue

            # ── Sub-commands within classifier ──
            if in_classifier:
                mm = _RE_HW_IF_MATCH_ACL.match(stripped)
                if mm:
                    classifiers[in_classifier]["if_matches"].append({
                        "type": "acl", "value": mm.group(1),
                    })
                    continue
                mm = _RE_HW_IF_MATCH_PREFIX.match(stripped)
                if mm:
                    classifiers[in_classifier]["if_matches"].append({
                        "type": "ip_prefix", "value": mm.group(1),
                    })
                    continue
                mm = _RE_HW_IF_MATCH_DSCP.match(stripped)
                if mm:
                    classifiers[in_classifier]["if_matches"].append({
                        "type": "dscp", "value": mm.group(1),
                    })
                    continue
                mm = _RE_HW_IF_MATCH_PROTO.match(stripped)
                if mm:
                    classifiers[in_classifier]["if_matches"].append({
                        "type": "protocol", "value": mm.group(1),
                    })
                    continue
                # if indent ≤ classifier_indent and not a sub-command, flush
                if indent <= classifier_indent and not stripped.startswith("if-match"):
                    self._flush_hw(in_classifier, in_behavior, in_policy)
                continue

            # ── Sub-commands within behavior ──
            if in_behavior:
                mm = _RE_HW_CAR.match(stripped)
                if mm:
                    behaviors[in_behavior]["actions"].append({
                        "type": "car", "value": mm.group(1),
                    })
                    continue
                mm = _RE_HW_REMARK_DSCP.match(stripped)
                if mm:
                    behaviors[in_behavior]["actions"].append({
                        "type": "remark_dscp", "value": mm.group(1),
                    })
                    continue
                mm = _RE_HW_QUEUE.match(stripped)
                if mm:
                    behaviors[in_behavior]["actions"].append({
                        "type": "queue", "value": mm.group(1),
                    })
                    continue
                mm = _RE_HW_PRIORITY.match(stripped)
                if mm:
                    behaviors[in_behavior]["actions"].append({
                        "type": "priority", "value": mm.group(1),
                    })
                    continue
                mm = _RE_HW_REDIRECT.match(stripped)
                if mm:
                    behaviors[in_behavior]["actions"].append({
                        "type": "redirect", "value": stripped[len("redirect"):].strip() or "yes",
                    })
                    continue
                if indent <= behavior_indent and not stripped[0].isspace():
                    self._flush_hw(in_classifier, in_behavior, in_policy)
                continue

            # ── Sub-commands within policy ──
            if in_policy:
                mm = _RE_HW_CLASSIFIER_BEHAVIOR.match(stripped)
                if mm:
                    policies[in_policy]["class_behaviors"].append({
                        "classifier": mm.group(1),
                        "behavior": mm.group(2),
                    })
                    continue
                if indent <= policy_indent and not stripped.startswith("classifier"):
                    self._flush_hw(in_classifier, in_behavior, in_policy)
                continue

            # ── Interface traffic-policy binding ──
            mm = _RE_HW_INTERFACE_POLICY.match(stripped)
            if mm and current_interface:
                interface_bindings.append({
                    "interface": current_interface,
                    "policy": mm.group(1),
                    "direction": mm.group(2).lower(),
                })
                continue

        self._flush_hw(in_classifier, in_behavior, in_policy)

    @staticmethod
    def _flush_hw(in_classifier, in_behavior, in_policy):
        pass

    # ═══════════════════════════════════════════════════════════════════
    # Cisco parser
    # ═══════════════════════════════════════════════════════════════════

    def _parse_cisco_qos(self, lines, class_maps, policy_maps, interface_bindings):
        in_class_map: Optional[str] = None
        in_policy_map: Optional[str] = None
        in_policy_class: Optional[str] = None
        current_interface: Optional[str] = None

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            # ── class-map ──
            m = _RE_CISCO_CLASS_MAP.match(stripped)
            if m:
                self._flush_cisco(in_class_map, in_policy_map, in_policy_class)
                in_class_map = m.group(1)
                class_maps[in_class_map] = {
                    "name": in_class_map, "matches": [],
                }
                in_policy_map = in_policy_class = None
                continue

            # ── policy-map ──
            m = _RE_CISCO_POLICY_MAP.match(stripped)
            if m:
                self._flush_cisco(in_class_map, in_policy_map, in_policy_class)
                in_policy_map = m.group(1)
                policy_maps[in_policy_map] = {
                    "name": in_policy_map, "classes": [],
                }
                in_class_map = in_policy_class = None
                continue

            # ── class inside policy-map ──
            if in_policy_map:
                m = _RE_CISCO_CLASS.match(stripped)
                if m:
                    in_policy_class = m.group(1)
                    policy_maps[in_policy_map]["classes"].append({
                        "class": in_policy_class, "actions": [],
                    })
                    continue

            # ── interface ──
            m = _RE_INTERFACE.match(stripped)
            if m:
                self._flush_cisco(in_class_map, in_policy_map, in_policy_class)
                current_interface = m.group(1)
                in_class_map = in_policy_map = in_policy_class = None
                continue

            # ── Sub-commands within class-map ──
            if in_class_map:
                mm = _RE_CISCO_MATCH_ACCESS.match(stripped)
                if mm:
                    class_maps[in_class_map]["matches"].append({
                        "type": "acl", "value": mm.group(1),
                    })
                    continue
                mm = _RE_CISCO_MATCH_DSCP.match(stripped)
                if mm:
                    class_maps[in_class_map]["matches"].append({
                        "type": "dscp", "value": mm.group(1),
                    })
                    continue
                mm = _RE_CISCO_MATCH_PROTO.match(stripped)
                if mm:
                    class_maps[in_class_map]["matches"].append({
                        "type": "protocol", "value": mm.group(1),
                    })
                    continue
                mm = _RE_CISCO_MATCH_PRECEDENCE.match(stripped)
                if mm:
                    class_maps[in_class_map]["matches"].append({
                        "type": "precedence", "value": mm.group(1),
                    })
                    continue
                # Exit class-map if next top-level command
                if not stripped.startswith("match") and stripped[0].isalpha():
                    in_class_map = None
                continue

            # ── Actions within policy-map class ──
            if in_policy_map and in_policy_class:
                mm = _RE_CISCO_POLICE.match(stripped)
                if mm:
                    self._add_cisco_action(policy_maps, in_policy_map, in_policy_class,
                                            "police", mm.group(1))
                    continue
                mm = _RE_CISCO_SHAPE.match(stripped)
                if mm:
                    self._add_cisco_action(policy_maps, in_policy_map, in_policy_class,
                                            "shape", mm.group(1))
                    continue
                mm = _RE_CISCO_BANDWIDTH.match(stripped)
                if mm:
                    self._add_cisco_action(policy_maps, in_policy_map, in_policy_class,
                                            "bandwidth", mm.group(1))
                    continue
                mm = _RE_CISCO_PRIORITY.match(stripped)
                if mm:
                    self._add_cisco_action(policy_maps, in_policy_map, in_policy_class,
                                            "priority", mm.group(1))
                    continue
                mm = _RE_CISCO_SET_DSCP.match(stripped)
                if mm:
                    self._add_cisco_action(policy_maps, in_policy_map, in_policy_class,
                                            "set_dscp", mm.group(1))
                    continue
                mm = _RE_CISCO_SET_PREC.match(stripped)
                if mm:
                    self._add_cisco_action(policy_maps, in_policy_map, in_policy_class,
                                            "set_precedence", mm.group(1))
                    continue
                # Exit class on next top-level command
                if stripped[0].isalpha() and not stripped.startswith(("police", "shape", "bandwidth", "priority", "set", "service-policy")):
                    in_policy_class = None
                continue

            # ── Interface service-policy binding ──
            mm = _RE_CISCO_SERVICE_POLICY.match(stripped)
            if mm and current_interface:
                interface_bindings.append({
                    "interface": current_interface,
                    "policy": mm.group(2),
                    "direction": mm.group(1).lower(),
                })
                continue

        self._flush_cisco(in_class_map, in_policy_map, in_policy_class)

    @staticmethod
    def _flush_cisco(in_class_map, in_policy_map, in_policy_class):
        pass

    @staticmethod
    def _add_cisco_action(policy_maps, pm_name, class_name, action_type, value):
        for cl in policy_maps[pm_name]["classes"]:
            if cl["class"] == class_name:
                cl["actions"].append({"type": action_type, "value": value})
                break

    # ═══════════════════════════════════════════════════════════════════
    # Rule builders
    # ═══════════════════════════════════════════════════════════════════

    def _build_hw_rules(self, classifiers, behaviors, policies,
                        interface_bindings, rules, missing, source_lines, refs):
        for pname, pdata in policies.items():
            classes = []
            for cb in pdata.get("class_behaviors", []):
                clf_name = cb["classifier"]
                beh_name = cb["behavior"]
                refs["classifier"].append(clf_name)
                refs["behavior"].append(beh_name)

                if clf_name not in classifiers:
                    missing.append(f"classifier {clf_name} 被 policy {pname} 引用但未定义")
                if beh_name not in behaviors:
                    missing.append(f"behavior {beh_name} 被 policy {pname} 引用但未定义")

                clf = classifiers.get(clf_name, {})
                matches = []
                for m in clf.get("if_matches", []):
                    if m["type"] == "acl":
                        refs["acl"].append(m["value"])
                    elif m["type"] == "ip_prefix":
                        refs["ip_prefix"].append(m["value"])
                    matches.append(m)

                beh = behaviors.get(beh_name, {})
                actions = list(beh.get("actions", []))

                classes.append({
                    "classifier": clf_name,
                    "behavior": beh_name,
                    "matches": matches,
                    "actions": actions,
                })

            policies[pname]["classes"] = classes

            # Check binding
            bound = [b for b in interface_bindings if b["policy"] == pname]
            if not bound:
                missing.append(f"traffic policy {pname} 定义存在但未绑定接口")
            else:
                for b in bound:
                    refs.setdefault("policy", []).append(b["policy"])

            rules.append({
                "policy_name": pname,
                "direction": bound[0]["direction"] if bound else None,
                "interface": bound[0]["interface"] if bound else None,
                "classes": classes,
                "source_lines": [],
            })

    def _build_cisco_rules(self, class_maps, policy_maps,
                           interface_bindings, rules, missing, source_lines, refs):
        for pm_name, pm_data in policy_maps.items():
            classes = []
            for cl_entry in pm_data.get("classes", []):
                cl_name = cl_entry["class"]
                actions = cl_entry.get("actions", [])
                refs["classifier"].append(cl_name)

                if cl_name not in class_maps and cl_name.lower() != "class-default":
                    missing.append(f"class-map {cl_name} 被 policy-map {pm_name} 引用但未定义——fatal")
                    classes.append({
                        "classifier": cl_name,
                        "matches": [],
                        "actions": actions,
                    })
                    continue

                cm = class_maps.get(cl_name, {})
                matches = []
                for m in cm.get("matches", []):
                    if m["type"] == "acl":
                        refs["acl"].append(m["value"])
                    matches.append(m)

                classes.append({
                    "classifier": cl_name,
                    "matches": matches,
                    "actions": actions,
                })

            # Check binding
            bound = [b for b in interface_bindings if b["policy"] == pm_name]
            if not bound:
                missing.append(f"policy-map {pm_name} 定义存在但未绑定接口（service-policy）")
            else:
                for b in bound:
                    refs.setdefault("policy", []).append(b["policy"])

            rules.append({
                "policy_name": pm_name,
                "direction": bound[0]["direction"] if bound else None,
                "interface": bound[0]["interface"] if bound else None,
                "classes": classes,
                "source_lines": [],
            })
