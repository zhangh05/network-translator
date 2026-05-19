from __future__ import annotations
import re
from typing import Any, Dict, List

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer


# ── Regex patterns ────────────────────────────────────────────────────────────

# Huawei/H3C: ip ip-prefix <name> permit|deny <prefix> [ge <len>] [le <len>]
_RE_HW_PREFIX = re.compile(
    r"^\s*ip\s+ip-prefix\s+(\S+)\s+(permit|deny)\s+(\S+)",
    re.IGNORECASE,
)

# Cisco: ip prefix-list <name> [seq <num>] permit|deny <prefix> [ge <len>] [le <len>]
_RE_CISCO_PREFIX = re.compile(
    r"^\s*ip\s+prefix-list\s+(\S+)(?:\s+seq\s+\S+)?\s+(permit|deny)\s+(\S+)",
    re.IGNORECASE,
)

# Huawei/H3C: route-policy <name> permit|deny node <id>
_RE_HW_POLICY_HEADER = re.compile(
    r"^\s*route-policy\s+(\S+)\s+(permit|deny)\s+node\s+(\S+)",
    re.IGNORECASE,
)

# Cisco: route-map <name> permit|deny <seq>
_RE_CISCO_RM_HEADER = re.compile(
    r"^\s*route-map\s+(\S+)\s+(permit|deny)\s+(\S+)",
    re.IGNORECASE,
)

# Huawei: if-match ip-prefix <name>
_RE_HW_IFMATCH_PREFIX = re.compile(
    r"^\s*if-match\s+ip-prefix\s+(\S+)",
    re.IGNORECASE,
)

# Huawei: if-match acl <id>
_RE_HW_IFMATCH_ACL = re.compile(
    r"^\s*if-match\s+acl\s+(\S+)",
    re.IGNORECASE,
)

# Cisco: match ip address prefix-list <name>
_RE_CISCO_MATCH_PREFIX = re.compile(
    r"^\s*match\s+ip\s+address\s+prefix-list\s+(\S+)",
    re.IGNORECASE,
)

# Cisco: match ip address <acl>
_RE_CISCO_MATCH_ACL = re.compile(
    r"^\s*match\s+ip\s+address\s+(\S+)",
    re.IGNORECASE,
)

# match community (Cisco) / if-match community (Huawei)
_RE_MATCH_COMMUNITY = re.compile(
    r"^\s*(?:if-match\s+)?match\s+community\s+(\S+)",
    re.IGNORECASE,
)

# Huawei apply commands
_RE_HW_APPLY = re.compile(
    r"^\s*apply\s+(\S+)\s+(.+)",
    re.IGNORECASE,
)

# Cisco set commands
_RE_CISCO_SET = re.compile(
    r"^\s*set\s+(\S+)\s+(.+)",
    re.IGNORECASE,
)

# Huawei: import-route <protocol> route-policy <name>
_RE_HW_IMPORT_ROUTE = re.compile(
    r"^\s*import-route\s+\S+(?:\s+\S+)*?\s+route-policy\s+(\S+)",
    re.IGNORECASE,
)

# Cisco: redistribute <protocol> route-map <name>
_RE_CISCO_REDISTRIBUTE = re.compile(
    r"^\s*redistribute\s+\S+(?:\s+\S+)*?\s+route-map\s+(\S+)",
    re.IGNORECASE,
)

# BGP neighbor route-policy (Huawei) / route-map (Cisco)
_RE_BGP_NEIGHBOR_POLICY = re.compile(
    r"^\s*peer\s+(\S+)\s+route-policy\s+(\S+)\s+(import|export)",
    re.IGNORECASE,
)
_RE_BGP_NEIGHBOR_RM = re.compile(
    r"^\s*neighbor\s+(\S+)\s+route-map\s+(\S+)\s+(in|out)",
    re.IGNORECASE,
)

# ── Vendor sets ────────────────────────────────────────────────────────────────
_HW_VENDORS = {"huawei", "h3c"}
_CISCO_VENDORS = {"cisco"}


def _normalize_set_type(raw_type: str) -> str:
    mapping = {
        "local-preference": "local_preference",
        "local_preference": "local_preference",
        "metric": "metric",
        "community": "community",
        "extcommunity": "extcommunity",
        "cost": "cost",
        "origin": "origin",
        "med": "med",
        "comm-list": "community",
        "ip": "ip_next_hop",
        "next-hop": "ip_next_hop",
        "tag": "tag",
        "weight": "weight",
    }
    return mapping.get(raw_type.lower().replace("-", "_"), raw_type.lower())


class RoutePolicyAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "route_policy"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        lines = config_text.splitlines()
        vendor_lower = vendor.lower()
        is_hw = vendor_lower in _HW_VENDORS
        is_cisco = vendor_lower in _CISCO_VENDORS

        if not is_hw and not is_cisco:
            return FeatureAnalysis(
                feature="route_policy",
                status="skipped",
                risk_level="info",
                notes=[f"Vendor {vendor} not supported for route_policy analysis"],
            )

        # Phase 1: collect prefix-list/ip-prefix definitions
        prefix_defs: Dict[str, List[str]] = {}
        for line in lines:
            stripped = line.strip()
            if is_hw:
                m = _RE_HW_PREFIX.match(stripped)
            else:
                m = _RE_CISCO_PREFIX.match(stripped)
            if m:
                name = m.group(1)
                prefix_defs.setdefault(name, []).append(stripped)

        # Phase 2: policy body parsing
        policies: Dict[str, Dict[str, Any]] = {}
        current_policy: str | None = None
        current_seq: Dict[str, Any] | None = None
        policy_indent = 0

        def _flush_seq():
            nonlocal current_seq
            if current_policy is not None and current_seq is not None:
                current_seq["source_lines"] = current_seq.get("source_lines", [])
                policies.setdefault(current_policy, {
                    "type": "route-policy" if is_hw else "route-map",
                    "sequences": [],
                })["sequences"].append(current_seq)
                current_seq = None

        def _start_policy(name: str, action: str, num: str, indent: int):
            nonlocal current_policy, policy_indent, current_seq
            _flush_seq()
            current_policy = name
            policy_indent = indent
            current_seq = {
                "num": num,
                "action": action.lower(),
                "matches": [],
                "sets": [],
                "source_lines": [],
                "raw_actions": [],
            }
            current_seq["source_lines"].append(stripped)

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            indent = len(line) - len(line.lstrip())

            if is_hw:
                m = _RE_HW_POLICY_HEADER.match(stripped)
            else:
                m = _RE_CISCO_RM_HEADER.match(stripped)

            if m:
                _flush_seq()
                name = m.group(1)
                action = m.group(2)
                num = m.group(3)
                _start_policy(name, action, num, indent)
                continue

            if current_policy is None:
                continue

            cur_indent = len(line) - len(line.lstrip())
            if cur_indent <= policy_indent and not stripped[0].isspace():
                _flush_seq()
                current_policy = None
                continue

            if current_seq is None:
                continue

            current_seq["source_lines"].append(stripped)

            # Huawei if-match
            if is_hw:
                mm = _RE_HW_IFMATCH_PREFIX.match(stripped)
                if mm:
                    current_seq["matches"].append({
                        "type": "prefix_list",
                        "name": mm.group(1),
                    })
                    current_seq.setdefault("references", {})\
                        .setdefault("prefix_list", set()).add(mm.group(1))
                    continue

                mm = _RE_HW_IFMATCH_ACL.match(stripped)
                if mm:
                    current_seq["matches"].append({
                        "type": "acl",
                        "name": mm.group(1),
                    })
                    current_seq.setdefault("references", {})\
                        .setdefault("acl", set()).add(mm.group(1))
                    continue

            # Cisco match
            if is_cisco:
                mm = _RE_CISCO_MATCH_PREFIX.match(stripped)
                if mm:
                    current_seq["matches"].append({
                        "type": "prefix_list",
                        "name": mm.group(1),
                    })
                    current_seq.setdefault("references", {})\
                        .setdefault("prefix_list", set()).add(mm.group(1))
                    continue

                mm = _RE_CISCO_MATCH_ACL.match(stripped)
                if mm:
                    val = mm.group(1)
                    if val.lower().startswith("prefix-list"):
                        # handled above
                        pass
                    else:
                        current_seq["matches"].append({
                            "type": "acl",
                            "name": val,
                        })
                        current_seq.setdefault("references", {})\
                            .setdefault("acl", set()).add(val)
                    continue

            # community (both)
            mm = _RE_MATCH_COMMUNITY.match(stripped)
            if mm:
                current_seq["matches"].append({
                    "type": "community",
                    "name": mm.group(1),
                })
                current_seq.setdefault("references", {})\
                    .setdefault("community_list", set()).add(mm.group(1))
                continue

            # apply (Huawei)
            if is_hw:
                mm = _RE_HW_APPLY.match(stripped)
                if mm:
                    set_type = _normalize_set_type(mm.group(1))
                    current_seq["sets"].append({
                        "type": set_type,
                        "value": mm.group(2).strip(),
                    })
                    current_seq["raw_actions"].append(f"apply {mm.group(1)} {mm.group(2)}")
                    continue

            # set (Cisco)
            if is_cisco:
                mm = _RE_CISCO_SET.match(stripped)
                if mm:
                    set_type = _normalize_set_type(mm.group(1))
                    current_seq["sets"].append({
                        "type": set_type,
                        "value": mm.group(2).strip(),
                    })
                    current_seq["raw_actions"].append(f"set {mm.group(1)} {mm.group(2)}")
                    continue

        _flush_seq()

        # Phase 3: collect external references (BGP/OSPF import-route/redistribute)
        external_refs: Dict[str, List[str]] = {}
        for line in lines:
            stripped = line.strip()
            if is_hw:
                m = _RE_HW_IMPORT_ROUTE.match(stripped)
                if m:
                    external_refs.setdefault(m.group(1), []).append(stripped)
                    continue
            if is_cisco:
                m = _RE_CISCO_REDISTRIBUTE.match(stripped)
                if m:
                    external_refs.setdefault(m.group(1), []).append(stripped)
                    continue

        # BGP neighbor references
        for line in lines:
            stripped = line.strip()
            if is_hw:
                m = _RE_BGP_NEIGHBOR_POLICY.match(stripped)
                if m:
                    external_refs.setdefault(m.group(2), []).append(stripped)
                    continue
            if is_cisco:
                m = _RE_BGP_NEIGHBOR_RM.match(stripped)
                if m:
                    external_refs.setdefault(m.group(2), []).append(stripped)
                    continue

        # Phase 4: risk analysis
        missing: List[str] = []
        all_rules: List[Dict[str, Any]] = []
        source_lines: List[str] = []
        policy_names: List[str] = list(policies.keys())
        prefix_names: List[str] = list(prefix_defs.keys())

        # Collect all referenced prefix-lists, ACLs, community-lists from policies
        ref_prefix: set = set()
        ref_acl: set = set()
        ref_community: set = set()

        for pname, pdata in policies.items():
            for seq in pdata["sequences"]:
                refs = seq.get("references", {})
                ref_prefix.update(refs.get("prefix_list", set()))
                ref_acl.update(refs.get("acl", set()))
                ref_community.update(refs.get("community_list", set()))
                all_rules.append({
                    "policy_name": pname,
                    "sequence": seq["num"],
                    "action": seq["action"],
                    "matches": seq["matches"],
                    "sets": seq["sets"],
                    "references": {
                        "prefix_list": list(refs.get("prefix_list", set())),
                        "acl": list(refs.get("acl", set())),
                        "community_list": list(refs.get("community_list", set())),
                    },
                    "source_lines": seq["source_lines"],
                })
                source_lines.extend(seq["source_lines"])

        # Check missing prefix-list definitions
        for ref in sorted(ref_prefix):
            if ref not in prefix_names:
                missing.append(f"prefix-list/ip-prefix {ref} 被引用但未定义")

        # Check missing ACL definitions (ACL analyzer provides deeper check)
        for ref in sorted(ref_acl):
            if not any(ref in l for l in lines if l.strip().lower().startswith("acl")
                       or l.strip().lower().startswith("access-list ")
                       or l.strip().lower().startswith("ip access-list ")):
                missing.append(f"ACL {ref} 被引用但在配置中未发现定义")

        # Check missing community-list definitions
        for ref in sorted(ref_community):
            missing.append(f"community-list {ref} 被引用但未发现定义（需人工确认）")

        # Check externally referenced but undefined policies
        for pname in external_refs:
            if pname not in policy_names:
                missing.append(f"route-policy/route-map {pname} 被 BGP/OSPF 引用但未定义——影响路由导入/导出路径")

        # Check for empty action / broken policy
        has_fatal = False
        for pname, pdata in policies.items():
            if not pdata["sequences"]:
                missing.append(f"route-policy/route-map {pname} 缺少策略序列")
                has_fatal = True

        # Determine risk
        risk = "info"
        manual_review = False
        if missing:
            risk = "warning"
            manual_review = True
        if has_fatal:
            risk = "fatal"

        # If nothing was found, skip
        if not policies and not prefix_defs and not external_refs:
            return FeatureAnalysis(
                feature="route_policy",
                status="skipped",
                risk_level="info",
                notes=["未发现 route-policy / route-map 配置"],
            )

        return FeatureAnalysis(
            feature="route_policy",
            status="analyzed",
            risk_level=risk,
            manual_review_required=manual_review or risk == "fatal",
            rules=all_rules,
            references={
                "policy": policy_names,
                "prefix_list": prefix_names,
                "external_refs": {
                    p: external_refs[p] for p in external_refs
                },
            },
            missing_context=missing,
            source_lines=list(dict.fromkeys(source_lines)),
            metadata={
                "policy_count": len(policies),
                "prefix_count": len(prefix_defs),
            },
        )
