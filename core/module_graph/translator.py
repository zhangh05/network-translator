from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from core.module_graph.builder import ordered_modules
from core.module_graph.models import ConfigModule, ModuleGraph
from core.rule_translator import RuleBasedTranslator


@dataclass(frozen=True)
class ModuleTranslationResult:
    module_id: str
    feature: str
    status: str
    source_lines: list[str]
    translated_lines: list[str] = field(default_factory=list)
    suggested_lines: list[str] = field(default_factory=list)
    manual_review_lines: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)
    consumes: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ModuleTranslationAssembly:
    results: list[ModuleTranslationResult]
    deployable_config: str
    manual_review_config: str
    coverage: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "results": [result.to_dict() for result in self.results],
            "deployable_config": self.deployable_config,
            "manual_review_config": self.manual_review_config,
            "coverage": self.coverage,
        }


def translate_module_graph(graph: ModuleGraph, from_vendor: str, to_vendor: str) -> ModuleTranslationAssembly:
    """Translate modules independently and assemble deterministic output.

    This is the first replacement layer for flat fallback translation. It keeps
    uncertain lines out of deployable config and records them as review evidence.
    """

    translator = RuleBasedTranslator()
    results: list[ModuleTranslationResult] = []
    deployable_chunks: list[str] = []
    review_chunks: list[str] = []

    for module in ordered_modules(graph):
        result = _translate_module(module, from_vendor, to_vendor, translator)
        results.append(result)
        if result.translated_lines:
            deployable_chunks.extend(result.translated_lines)
        if result.manual_review_lines:
            review_chunks.extend(result.manual_review_lines)

    return ModuleTranslationAssembly(
        results=results,
        deployable_config="\n".join(_dedupe_adjacent_blank_lines(deployable_chunks)).strip(),
        manual_review_config="\n".join(_dedupe_adjacent_blank_lines(review_chunks)).strip(),
        coverage=_translation_coverage(graph, results),
    )


def _translation_coverage(graph: ModuleGraph, results: list[ModuleTranslationResult]) -> dict:
    module_ids = [module.module_id for module in graph.modules]
    result_ids = [result.module_id for result in results]
    missing = [module_id for module_id in module_ids if module_id not in set(result_ids)]
    status_counts: dict[str, int] = {}
    for result in results:
        status_counts[result.status] = status_counts.get(result.status, 0) + 1
    return {
        "total_modules": len(module_ids),
        "result_modules": len(result_ids),
        "translated_modules": status_counts.get("translated", 0),
        "partial_modules": status_counts.get("partial", 0),
        "semantic_near_modules": status_counts.get("semantic_near", 0),
        "manual_review_modules": status_counts.get("manual_review", 0),
        "unsupported_modules": status_counts.get("unsupported", 0),
        "missing_module_ids": missing,
        "status_counts": dict(sorted(status_counts.items())),
        "all_modules_accounted": not missing and len(result_ids) == len(module_ids),
    }


def _translate_module(
    module: ConfigModule,
    from_vendor: str,
    to_vendor: str,
    translator: RuleBasedTranslator,
) -> ModuleTranslationResult:
    source_text = "\n".join(module.source_lines)
    if module.status == "manual_review":
        semantic_near = _semantic_near_result(module, from_vendor, to_vendor)
        if semantic_near is not None:
            return semantic_near
        return ModuleTranslationResult(
            module_id=module.module_id,
            feature=module.feature,
            status="manual_review",
            source_lines=module.source_lines,
            manual_review_lines=_source_review_lines(module),
            provides=module.provides,
            consumes=module.consumes,
            depends_on=module.depends_on,
            reason=module.manual_review_reason,
        )

    if module.feature == "acl_binding":
        return _translate_acl_binding_module(module, from_vendor, to_vendor, translator)
    if module.feature.startswith("ospf."):
        return _translate_ospf_module(module, from_vendor, to_vendor, translator)
    if module.feature.startswith("bgp."):
        return _translate_bgp_module(module, from_vendor, to_vendor, translator)

    translated = translator.translate(source_text, from_vendor, to_vendor)
    body = _extract_config_block(translated).strip()
    translated_lines: list[str] = []
    review_lines: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "MANUAL_REVIEW" in stripped:
            review_lines.append(line)
        else:
            translated_lines.append(line)

    status = "translated" if translated_lines else "manual_review"
    reason = "" if translated_lines else "该模块没有生成确定的可部署配置"
    if review_lines and translated_lines:
        status = "partial"
        reason = "模块部分命令需要人工复核"

    return ModuleTranslationResult(
        module_id=module.module_id,
        feature=module.feature,
        status=status,
        source_lines=module.source_lines,
        translated_lines=translated_lines,
        manual_review_lines=review_lines or ([] if translated_lines else _source_review_lines(module, reason)),
        provides=module.provides,
        consumes=module.consumes,
        depends_on=module.depends_on,
        reason=reason,
    )


def _translate_ospf_module(
    module: ConfigModule,
    from_vendor: str,
    to_vendor: str,
    translator: RuleBasedTranslator,
) -> ModuleTranslationResult:
    if module.status == "manual_review":
        return ModuleTranslationResult(
            module_id=module.module_id,
            feature=module.feature,
            status="manual_review",
            source_lines=module.source_lines,
            manual_review_lines=_source_review_lines(module),
            provides=module.provides,
            consumes=module.consumes,
            depends_on=module.depends_on,
            reason=module.manual_review_reason,
        )

    process_id = _first_resource_value(module.provides + module.consumes, "ospf:")
    if ":area:" in process_id:
        process_id = process_id.split(":area:", 1)[0]
    source_text = "\n".join(module.source_lines)
    if process_id and not _starts_with_ospf_header(source_text):
        header = f"router ospf {process_id}" if from_vendor in ("cisco", "ruijie") else f"ospf {process_id}"
        source_text = f"{header}\n " + "\n ".join(module.source_lines)

    translated = translator.translate(source_text, from_vendor, to_vendor)
    body = _extract_config_block(translated).strip()
    translated_lines: list[str] = []
    review_lines: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "MANUAL_REVIEW" in stripped:
            review_lines.append(line)
        else:
            translated_lines.append(line)

    status = "translated" if translated_lines else "manual_review"
    reason = "" if translated_lines else "OSPF 子模块没有生成确定的可部署配置"
    if review_lines and translated_lines:
        status = "partial"
        reason = "OSPF 子模块部分命令需要人工复核"
    return ModuleTranslationResult(
        module_id=module.module_id,
        feature=module.feature,
        status=status,
        source_lines=module.source_lines,
        translated_lines=translated_lines,
        manual_review_lines=review_lines or ([] if translated_lines else _source_review_lines(module, reason)),
        provides=module.provides,
        consumes=module.consumes,
        depends_on=module.depends_on,
        reason=reason,
    )


def _translate_bgp_module(
    module: ConfigModule,
    from_vendor: str,
    to_vendor: str,
    translator: RuleBasedTranslator,
) -> ModuleTranslationResult:
    if module.status == "manual_review":
        return ModuleTranslationResult(
            module_id=module.module_id,
            feature=module.feature,
            status="manual_review",
            source_lines=module.source_lines,
            manual_review_lines=_source_review_lines(module),
            provides=module.provides,
            consumes=module.consumes,
            depends_on=module.depends_on,
            reason=module.manual_review_reason,
        )

    asn = _first_resource_value(module.provides + module.consumes, "bgp:")
    if ":neighbor:" in asn:
        asn = asn.split(":neighbor:", 1)[0]
    source_text = "\n".join(module.source_lines)
    if asn and not _starts_with_bgp_header(source_text):
        header = f"router bgp {asn}" if from_vendor in ("cisco", "ruijie") else f"bgp {asn}"
        source_text = f"{header}\n " + "\n ".join(module.source_lines)

    translated = translator.translate(source_text, from_vendor, to_vendor)
    body = _extract_config_block(translated).strip()
    translated_lines: list[str] = []
    review_lines: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "MANUAL_REVIEW" in stripped:
            review_lines.append(line)
        else:
            translated_lines.append(line)

    status = "translated" if translated_lines else "manual_review"
    reason = "" if translated_lines else "BGP 子模块没有生成确定的可部署配置"
    if review_lines and translated_lines:
        status = "partial"
        reason = "BGP 子模块部分命令需要人工复核"
    return ModuleTranslationResult(
        module_id=module.module_id,
        feature=module.feature,
        status=status,
        source_lines=module.source_lines,
        translated_lines=translated_lines,
        manual_review_lines=review_lines or ([] if translated_lines else _source_review_lines(module, reason)),
        provides=module.provides,
        consumes=module.consumes,
        depends_on=module.depends_on,
        reason=reason,
    )


def _translate_acl_binding_module(
    module: ConfigModule,
    from_vendor: str,
    to_vendor: str,
    translator: RuleBasedTranslator,
) -> ModuleTranslationResult:
    interface_name = _first_resource_value(module.consumes, "interface:")
    source_text = "\n".join(module.source_lines)
    if interface_name:
        source_text = f"interface {interface_name}\n " + "\n ".join(module.source_lines)

    translated = translator.translate(source_text, from_vendor, to_vendor)
    body = _extract_config_block(translated).strip()
    translated_lines: list[str] = []
    review_lines: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "MANUAL_REVIEW" in stripped:
            review_lines.append(line)
        else:
            translated_lines.append(line)

    status = "translated" if translated_lines else "manual_review"
    reason = "" if translated_lines else "ACL 绑定没有生成确定的可部署配置"
    return ModuleTranslationResult(
        module_id=module.module_id,
        feature=module.feature,
        status=status,
        source_lines=module.source_lines,
        translated_lines=translated_lines,
        manual_review_lines=review_lines or ([] if translated_lines else _source_review_lines(module, reason)),
        provides=module.provides,
        consumes=module.consumes,
        depends_on=module.depends_on,
        reason=reason,
    )


def _first_resource_value(resources: list[str], prefix: str) -> str:
    for resource in resources:
        if resource.startswith(prefix):
            return resource[len(prefix):]
    return ""


def _starts_with_ospf_header(text: str) -> bool:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    return bool(re.match(r"^(?:ospf|router\s+ospf)\s+\S+", first, re.IGNORECASE))


def _starts_with_bgp_header(text: str) -> bool:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    return bool(re.match(r"^(?:bgp|router\s+bgp)\s+\S+", first, re.IGNORECASE))


def _source_review_lines(module: ConfigModule, reason: str = "") -> list[str]:
    reason_text = reason or module.manual_review_reason or "需要人工复核"
    lines = [f"# MODULE_REVIEW {module.module_id} {module.feature}: {reason_text}"]
    lines.extend(f"# SOURCE line {module.start_line + idx}: {line}" for idx, line in enumerate(module.source_lines))
    return lines


def _semantic_near_result(module: ConfigModule, from_vendor: str, to_vendor: str) -> ModuleTranslationResult | None:
    suggested: list[str] = []
    if module.feature.startswith("qos."):
        suggested = _qos_suggested_lines(module, from_vendor, to_vendor)
    elif module.feature == "route_policy":
        suggested = _route_policy_suggested_lines(module, from_vendor, to_vendor)
    elif module.feature == "bgp.policy":
        suggested = _bgp_policy_suggested_lines(module, from_vendor, to_vendor)
    elif module.feature.startswith("fhrp."):
        suggested = _fhrp_suggested_lines(module, from_vendor, to_vendor)
    elif module.feature in ("dhcp.relay", "dhcp.relay.binding"):
        suggested = _dhcp_relay_suggested_lines(module, from_vendor, to_vendor)
    elif module.feature in ("management.ntp", "management.snmp", "management.logging"):
        suggested = _management_suggested_lines(module, from_vendor, to_vendor)
    elif module.feature == "static_route.option":
        suggested = _static_route_option_suggested_lines(module, from_vendor, to_vendor)
    elif module.feature == "lacp.tuning":
        suggested = _lacp_tuning_suggested_lines(module, from_vendor, to_vendor)
    elif module.feature == "stp.mstp":
        suggested = _mstp_suggested_lines(module, from_vendor, to_vendor)
    elif module.feature.startswith("ospf."):
        suggested = _ospf_suggested_lines(module, from_vendor, to_vendor)
    elif module.feature.startswith("rip."):
        suggested = _rip_suggested_lines(module, from_vendor, to_vendor)
    elif module.feature.startswith("isis."):
        suggested = _isis_suggested_lines(module, from_vendor, to_vendor)
    elif module.feature.startswith("multicast"):
        suggested = _multicast_suggested_lines(module, from_vendor, to_vendor)
    elif module.feature.startswith("access."):
        suggested = _access_suggested_lines(module, from_vendor, to_vendor)
    if not suggested:
        return None
    reason = module.manual_review_reason or "该模块已生成语义相近建议，动作细节需人工确认"
    return ModuleTranslationResult(
        module_id=module.module_id,
        feature=module.feature,
        status="semantic_near",
        source_lines=module.source_lines,
        suggested_lines=suggested,
        manual_review_lines=_source_review_lines(module, reason),
        provides=module.provides,
        consumes=module.consumes,
        depends_on=module.depends_on,
        reason=reason,
    )


def _qos_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    source_text = "\n".join(module.source_lines)
    target = (to_vendor or "").lower()
    if module.feature == "qos.classifier":
        name = _first_resource_value(module.provides, "qos-classifier:") or _first_word_after(module.source_lines[0], "classifier")
        acl_refs = [item.split(":", 1)[1] for item in module.consumes if item.startswith("acl:")]
        if target == "cisco":
            lines = [f"class-map match-all {name}"]
            lines.extend(f" match access-group {acl}" for acl in acl_refs)
            if len(lines) == 1:
                lines.append(" ! confirm match conditions manually")
            return lines
        return [f"traffic classifier {name}", *[f" if-match acl {acl}" for acl in acl_refs]]

    if module.feature == "qos.behavior":
        name = _first_resource_value(module.provides, "qos-behavior:") or _first_word_after(module.source_lines[0], "behavior")
        dscp = _extract_first(r"\b(?:remark|set)\s+dscp\s+(\S+)", source_text)
        cir = _extract_first(r"\b(?:car|police)\s+(?:cir\s+)?(\d+)", source_text)
        if target == "cisco":
            lines = [f"policy-map {name}", " class class-default"]
            if dscp:
                lines.append(f"  set dscp {dscp}")
            if cir:
                lines.append(f"  police {cir}")
            if len(lines) == 2:
                lines.append("  ! confirm QoS action manually")
            return lines
        lines = [f"traffic behavior {name}"]
        if dscp:
            lines.append(f" remark dscp {dscp}")
        if cir:
            lines.append(f" car cir {cir}")
        if len(lines) == 1:
            lines.append(" # confirm QoS action manually")
        return lines

    if module.feature == "qos.policy":
        name = _first_resource_value(module.provides, "qos-policy:") or _first_word_after(module.source_lines[0], "policy")
        pairs = _extract_qos_policy_pairs(source_text)
        if target == "cisco":
            lines = [f"policy-map {name}"]
            if pairs:
                for classifier, behavior in pairs:
                    lines.append(f" class {classifier}")
                    lines.append(f"  ! confirm behavior {behavior} actions manually")
            else:
                lines.append(" class class-default")
                lines.append("  ! confirm QoS actions manually")
            return lines
        lines = [f"traffic policy {name}"]
        if pairs:
            lines.extend(f" classifier {classifier} behavior {behavior}" for classifier, behavior in pairs)
        else:
            lines.append(" # confirm classifier/behavior mapping manually")
        return lines
    return []


def _route_policy_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    source_text = "\n".join(module.source_lines)
    target = (to_vendor or "").lower()
    name = _first_resource_value(module.provides, "route-policy:") or _extract_route_policy_name(source_text)
    seq = _extract_first(r"\b(?:node|permit|deny)\s+(\d+)\b", module.source_lines[0] if module.source_lines else "")
    seq = seq or "10"
    action = "deny" if re.search(r"\bdeny\b", module.source_lines[0] if module.source_lines else "", re.IGNORECASE) else "permit"
    acl = _extract_first(r"\b(?:if-match\s+acl|match\s+ip\s+address)\s+(\S+)", source_text)
    prefix = _extract_first(r"\b(?:if-match\s+ip-prefix|match\s+ip\s+address\s+prefix-list)\s+(\S+)", source_text)
    local_pref = _extract_first(r"\b(?:apply|set)\s+local-preference\s+(\S+)", source_text)
    med = _extract_first(r"\b(?:apply|set)\s+(?:cost|metric|med)\s+(\S+)", source_text)

    if target == "cisco":
        lines = [f"route-map {name} {action} {seq}"]
        if prefix:
            lines.append(f" match ip address prefix-list {prefix}")
        elif acl:
            lines.append(f" match ip address {acl}")
        if local_pref:
            lines.append(f" set local-preference {local_pref}")
        if med:
            lines.append(f" set metric {med}")
        if len(lines) == 1:
            lines.append(" ! confirm match/set clauses manually")
        return lines

    lines = [f"route-policy {name} {action} node {seq}"]
    if prefix:
        lines.append(f" if-match ip-prefix {prefix}")
    elif acl:
        lines.append(f" if-match acl {acl}")
    if local_pref:
        lines.append(f" apply local-preference {local_pref}")
    if med:
        lines.append(f" apply cost {med}")
    if len(lines) == 1:
        lines.append(" # confirm match/apply clauses manually")
    return lines


def _bgp_policy_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    target = (to_vendor or "").lower()
    lines: list[str] = []
    for raw_line in module.source_lines:
        line = raw_line.strip()
        peer = _extract_first(r"\bpeer\s+(\S+)\s+route-policy\s+(\S+)\s+(import|export)\b", line)
        if peer:
            match = re.search(r"\bpeer\s+(\S+)\s+route-policy\s+(\S+)\s+(import|export)\b", line, re.IGNORECASE)
            if match and target == "cisco":
                direction = "in" if match.group(3).lower() == "import" else "out"
                lines.append(f"neighbor {match.group(1)} route-map {match.group(2)} {direction}")
            elif match:
                lines.append(f"peer {match.group(1)} route-policy {match.group(2)} {match.group(3)}")
            continue
        match = re.search(r"\bneighbor\s+(\S+)\s+route-map\s+(\S+)\s+(in|out)\b", line, re.IGNORECASE)
        if match and target != "cisco":
            direction = "import" if match.group(3).lower() == "in" else "export"
            lines.append(f"peer {match.group(1)} route-policy {match.group(2)} {direction}")
        elif match:
            lines.append(f"neighbor {match.group(1)} route-map {match.group(2)} {match.group(3)}")
    if not lines:
        lines.append("# confirm BGP policy attachment manually" if target != "cisco" else "! confirm BGP policy attachment manually")
    return lines


def _fhrp_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    target = (to_vendor or "").lower()
    source_text = "\n".join(module.source_lines)
    interface = _first_resource_value(module.consumes, "interface:")
    vlan_id = _extract_first(r"(?:Vlanif|Vlan|Vlan-interface)(\d+)", interface)
    group = _extract_first(r"\b(?:vrid|standby)\s+(\S+)", source_text) or _extract_first(r":(\S+)$", _first_resource_value(module.provides, "vrrp:") or _first_resource_value(module.provides, "hsrp:")) or "1"
    vip = _extract_first(r"\b(?:virtual-ip|ip)\s+(\d+\.\d+\.\d+\.\d+)", source_text)
    priority = _extract_first(r"\bpriority\s+(\d+)", source_text)
    preempt = bool(re.search(r"\b(?:preempt|preempt-mode)\b", source_text, re.IGNORECASE))
    if target == "cisco":
        if not vlan_id:
            return []
        lines = [f"interface Vlan{vlan_id}"]
        if vip:
            lines.append(f" standby {group} ip {vip}")
        if priority:
            lines.append(f" standby {group} priority {priority}")
        if preempt:
            lines.append(f" standby {group} preempt")
        if len(lines) == 1:
            lines.append(f" ! confirm HSRP group {group} manually")
        return lines
    if not vlan_id:
        return []
    lines = [f"interface Vlanif{vlan_id}"]
    if vip:
        lines.append(f" vrrp vrid {group} virtual-ip {vip}")
    if priority:
        lines.append(f" vrrp vrid {group} priority {priority}")
    if preempt:
        lines.append(f" vrrp vrid {group} preempt-mode")
    if len(lines) == 1:
        lines.append(f" # confirm VRRP group {group} manually")
    return lines


def _dhcp_relay_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    target = (to_vendor or "").lower()
    source_text = "\n".join(module.source_lines)
    servers = _unique(re.findall(r"\b(?:server-ip|server-address|helper-address|destination)\s+(\d+\.\d+\.\d+\.\d+)", source_text, flags=re.IGNORECASE))
    if not servers:
        return []
    if target == "cisco":
        return [f"ip helper-address {server}" for server in servers]
    if target in ("huawei", "h3c", "ruijie"):
        keyword = "dhcp relay server-address" if target in ("h3c", "ruijie") else "dhcp relay server-ip"
        return [f"{keyword} {server}" for server in servers]
    return []


def _management_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    target = (to_vendor or "").lower()
    source_text = "\n".join(module.source_lines)
    if module.feature == "management.snmp":
        if re.search(r"\bcommunity\b", source_text, re.IGNORECASE):
            if target == "cisco":
                return ["snmp-server community <redacted> RO"]
            return ["snmp-agent community read cipher <redacted>"]
        return []
    if module.feature == "management.logging":
        hosts = _unique(re.findall(r"\b(?:loghost|logging\s+host)\s+(\d+\.\d+\.\d+\.\d+)", source_text, flags=re.IGNORECASE))
        if target == "cisco":
            return [f"logging host {host}" for host in hosts]
        return [f"info-center loghost {host}" for host in hosts]
    if module.feature == "management.ntp":
        servers = _unique(re.findall(r"\b(?:unicast-server|ntp\s+server)\s+(\d+\.\d+\.\d+\.\d+)", source_text, flags=re.IGNORECASE))
        if target == "cisco":
            return [f"ntp server {server}" for server in servers]
        return [f"ntp-service unicast-server {server}" for server in servers]
    return []


def _static_route_option_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    line = next((item.strip() for item in module.source_lines if item.strip()), "")
    match = re.search(
        r"\bip\s+route-static\s+(?:vpn-instance\s+(\S+)\s+)?(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
        line,
        re.IGNORECASE,
    )
    target = (to_vendor or "").lower()
    if match and target == "cisco":
        vrf, dest, mask, nexthop = match.groups()
        prefix = f"ip route vrf {vrf}" if vrf else "ip route"
        return [f"{prefix} {dest} {mask} {nexthop}", "! confirm track/BFD/tag/preference/description options manually"]
    match = re.search(
        r"\bip\s+route(?:\s+vrf\s+(\S+))?\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
        line,
        re.IGNORECASE,
    )
    if match:
        vrf, dest, mask, nexthop = match.groups()
        prefix = f"ip route-static vpn-instance {vrf}" if vrf else "ip route-static"
        return [f"{prefix} {dest} {mask} {nexthop}", "# confirm track/BFD/tag/preference/description options manually"]
    return []


def _lacp_tuning_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    source_text = "\n".join(module.source_lines)
    target = (to_vendor or "").lower()
    lines: list[str] = []
    if re.search(r"\btimeout\s+fast\b", source_text, re.IGNORECASE):
        lines.append("lacp rate fast" if target == "cisco" else "lacp timeout fast")
    if re.search(r"\btimeout\s+slow\b", source_text, re.IGNORECASE):
        lines.append("lacp rate normal" if target == "cisco" else "lacp timeout slow")
    if re.search(r"\bpreempt\b", source_text, re.IGNORECASE):
        lines.append("! confirm LACP preempt behavior manually" if target == "cisco" else "# confirm LACP preempt behavior manually")
    if re.search(r"\bpriority\s+(\d+)", source_text, re.IGNORECASE):
        priority = _extract_first(r"\bpriority\s+(\d+)", source_text)
        lines.append(f"lacp port-priority {priority}" if target == "cisco" else f"lacp priority {priority}")
    return lines


def _mstp_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    source_text = "\n".join(module.source_lines)
    target = (to_vendor or "").lower()
    name = _extract_first(r"\b(?:region-name|name)\s+(\S+)", source_text)
    revision = _extract_first(r"\b(?:revision-level|revision)\s+(\S+)", source_text)
    instances = re.findall(r"\binstance\s+(\d+)\s+vlan\s+(.+)", source_text, flags=re.IGNORECASE)
    if target == "cisco":
        lines = ["spanning-tree mst configuration"]
        if name:
            lines.append(f" name {name}")
        if revision:
            lines.append(f" revision {revision}")
        lines.extend(f" instance {instance} vlan {vlans.strip()}" for instance, vlans in instances)
        if len(lines) == 1:
            lines.append(" ! confirm MST region manually")
        return lines
    lines = ["stp region-configuration"]
    if name:
        lines.append(f" region-name {name}")
    if revision:
        lines.append(f" revision-level {revision}")
    lines.extend(f" instance {instance} vlan {vlans.strip()}" for instance, vlans in instances)
    lines.append(" active region-configuration")
    return lines


def _ospf_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    source_text = "\n".join(module.source_lines)
    target = (to_vendor or "").lower()
    if module.feature == "ospf.authentication":
        area = _extract_first(r":area:([^:]+)", " ".join(module.consumes + module.provides)) or "0"
        area = "0" if area == "0.0.0.0" else area
        if target == "cisco":
            return [f"area {area} authentication message-digest", "! confirm OSPF key-chain/key-id manually"]
        return [f"area {area}", " authentication-mode md5 <redacted>", "# confirm OSPF key-chain/key-id manually"]
    if module.feature == "ospf.redistribute":
        proto = _extract_first(r"\b(?:import-route|redistribute)\s+(\S+)", source_text) or "static"
        return [f"redistribute {proto}" if target == "cisco" else f"import-route {proto}"]
    if module.feature == "ospf.area_special":
        if re.search(r"\bnssa\b", source_text, re.IGNORECASE):
            return ["area 0 nssa" if target == "cisco" else "nssa", _comment_for(target, "confirm NSSA options manually")]
        if re.search(r"\bstub\b", source_text, re.IGNORECASE):
            return ["area 0 stub" if target == "cisco" else "stub", _comment_for(target, "confirm stub/no-summary options manually")]
        if re.search(r"\bvirtual-link\b", source_text, re.IGNORECASE):
            return [_comment_for(target, "confirm OSPF virtual-link manually")]
    if module.feature == "ospf.interface_tuning":
        lines: list[str] = []
        cost = _extract_first(r"\bcost\s+(\d+)", source_text)
        if cost:
            lines.append(f"ip ospf cost {cost}" if target == "cisco" else f"ospf cost {cost}")
        network_type = _extract_first(r"\bnetwork-type\s+(\S+)", source_text)
        if network_type:
            lines.append(f"ip ospf network {network_type}" if target == "cisco" else f"ospf network-type {network_type}")
        return lines
    return []


def _rip_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    source_text = "\n".join(module.source_lines)
    target = (to_vendor or "").lower()
    process = _first_resource_value(module.provides + module.consumes, "rip:") or "1"
    process = "1" if process == "default" else process
    if module.feature == "rip.process":
        return ["router rip"] if target == "cisco" else [f"rip {process}"]
    if module.feature == "rip.network":
        network = _extract_first(r"\bnetwork\s+(\S+)", source_text)
        return [f"network {network}"] if network else []
    if module.feature == "rip.redistribute":
        proto = _extract_first(r"\b(?:redistribute|import-route)\s+(\S+)", source_text) or "static"
        return [f"redistribute {proto}" if target == "cisco" else f"import-route {proto}"]
    return []


def _isis_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    source_text = "\n".join(module.source_lines)
    target = (to_vendor or "").lower()
    process = _first_resource_value(module.provides + module.consumes, "isis:") or "1"
    process = "1" if process == "default" else process
    if module.feature == "isis.process":
        return [f"router isis {process}" if target == "cisco" else f"isis {process}"]
    if module.feature == "isis.network_entity":
        net = _extract_first(r"\b(?:network-entity|net)\s+(\S+)", source_text)
        if not net:
            return []
        return [f"net {net}" if target == "cisco" else f"network-entity {net}"]
    if module.feature == "isis.interface_tuning":
        lines: list[str] = []
        if re.search(r"\bcost-style\s+wide\b|\bmetric-style\s+wide\b", source_text, re.IGNORECASE):
            lines.append("metric-style wide" if target == "cisco" else "cost-style wide")
        metric = _extract_first(r"\bmetric\s+(\d+)", source_text)
        if metric:
            lines.append(f"isis metric {metric}" if target == "cisco" else f"isis cost {metric}")
        if re.search(r"\bauthentication\b", source_text, re.IGNORECASE):
            lines.append(_comment_for(target, "confirm IS-IS authentication manually"))
        return lines
    if module.feature == "isis.redistribute":
        proto = _extract_first(r"\b(?:redistribute|import-route)\s+(\S+)", source_text) or "static"
        return [f"redistribute {proto}" if target == "cisco" else f"import-route {proto}"]
    return []


def _multicast_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    source_text = "\n".join(module.source_lines)
    target = (to_vendor or "").lower()
    if module.feature == "multicast.rp":
        rp = _extract_first(r"\b(?:rp-address|static-rp)\s+(\d+\.\d+\.\d+\.\d+)", source_text)
        if target == "cisco":
            lines = ["ip multicast-routing"]
            if rp:
                lines.append(f"ip pim rp-address {rp}")
            return lines
        lines = ["multicast routing-enable"]
        if rp:
            lines.append(f"static-rp {rp}")
        return lines
    if module.feature in ("multicast", "multicast.interface", "multicast.igmp_tuning"):
        lines: list[str] = []
        if re.search(r"\bpim\b", source_text, re.IGNORECASE):
            lines.append("ip pim sparse-mode" if target == "cisco" else "pim sm")
        if re.search(r"\bigmp\b", source_text, re.IGNORECASE):
            lines.append("ip igmp version 2" if target == "cisco" else "igmp enable")
        if not lines and re.search(r"\bmulticast\b", source_text, re.IGNORECASE):
            lines.append("ip multicast-routing" if target == "cisco" else "multicast routing-enable")
        return lines
    return []


def _access_suggested_lines(module: ConfigModule, from_vendor: str, to_vendor: str) -> list[str]:
    source_text = "\n".join(module.source_lines)
    target = (to_vendor or "").lower()
    if module.feature in ("access.auth_profile", "access.dot1x", "access.mac_auth", "access.radius_binding"):
        if target == "cisco":
            lines = ["aaa authentication dot1x default group radius"]
            if re.search(r"\bauthorization\b|access-domain|domain\\b", source_text, re.IGNORECASE):
                lines.append("aaa authorization network default group radius")
            lines.append("! confirm RADIUS/TACACS server groups and fail actions manually")
            return lines
        return ["authentication-profile name <confirm-profile>", "# confirm dot1x/mac-auth/domain/radius scheme manually"]
    if module.feature == "access.interface_binding":
        interface = _first_resource_value(module.consumes, "interface:")
        lines = [f"interface {interface}"] if interface else []
        if target == "cisco":
            if re.search(r"\bdot1x\b|authentication-profile|authentication\\s+port-control", source_text, re.IGNORECASE):
                lines.append(" authentication port-control auto")
                lines.append(" dot1x pae authenticator")
            if re.search(r"\bmac-authentication\b|\\bmab\\b", source_text, re.IGNORECASE):
                lines.append(" mab")
            if re.search(r"\bhost-mode|multi-auth\b", source_text, re.IGNORECASE):
                lines.append(" access-session host-mode multi-auth")
            lines.append(" ! confirm access-session event/fail policy manually")
            return lines
        lines.append(" authentication-profile <confirm-profile>")
        lines.append(" # confirm dot1x/mac-auth/access-domain manually")
        return lines
    if module.feature == "access.portal":
        return [_comment_for(target, "confirm portal server and redirect behavior manually")]
    return []


def _comment_for(target: str, text: str) -> str:
    return f"! {text}" if (target or "").lower() == "cisco" else f"# {text}"


def _extract_route_policy_name(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    for pattern in (
        r"^route-policy\s+(\S+)",
        r"^route-map\s+(\S+)",
    ):
        match = re.match(pattern, first, re.IGNORECASE)
        if match:
            return match.group(1)
    return "POLICY"


def _unique(values) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _first_word_after(line: str, keyword: str) -> str:
    m = re.search(rf"\b{re.escape(keyword)}\s+(\S+)", line or "", re.IGNORECASE)
    return m.group(1) if m else "UNNAMED"


def _extract_first(pattern: str, text: str) -> str:
    m = re.search(pattern, text or "", re.IGNORECASE)
    return m.group(1) if m else ""


def _extract_qos_policy_pairs(text: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for m in re.finditer(r"\bclassifier\s+(\S+)\s+behavior\s+(\S+)", text or "", re.IGNORECASE):
        pairs.append((m.group(1), m.group(2)))
    return pairs


def _dedupe_adjacent_blank_lines(lines: list[str]) -> list[str]:
    output: list[str] = []
    previous_blank = False
    for line in lines:
        is_blank = not line.strip()
        if is_blank and previous_blank:
            continue
        output.append(line)
        previous_blank = is_blank
    return output


def _extract_config_block(text: str) -> str:
    match = re.search(r"```[a-zA-Z0-9_-]*\n(.*?)```", text or "", re.DOTALL)
    if match:
        return match.group(1).strip()
    return text or ""
