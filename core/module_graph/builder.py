from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from core.module_graph.models import ConfigModule, ModuleCoupling, ModuleDependency, ModuleGraph
from core.parser.block_splitter import ConfigBlock, split_config_by_feature


_MANUAL_REVIEW_FEATURES = {"unknown", "aaa", "qos"}


@dataclass
class _ModuleSpec:
    feature: str
    start_line: int
    end_line: int
    source_lines: list[str]
    provides: set[str] = field(default_factory=set)
    consumes: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    status: str = "translatable"
    manual_review_reason: str = ""


def build_module_graph(config_text: str, vendor: str = "unknown") -> ModuleGraph:
    """Build an auditable module graph from source config text.

    The graph is intentionally a decomposition layer, not a translation engine.
    It records which source blocks provide or consume named resources so later
    translation can work module-by-module without silently dropping couplings.
    """

    modules: list[ConfigModule] = []
    index = 1
    for block in split_config_by_feature(config_text, vendor):
        for spec in _module_specs_from_block(block):
            modules.append(_module_from_spec(spec, index, vendor or "unknown"))
            index += 1
    graph = ModuleGraph(modules=modules)
    _attach_dependencies(graph)
    return graph


def ordered_modules(graph: ModuleGraph) -> list[ConfigModule]:
    """Return modules with providers before consumers when dependencies exist."""

    module_by_id = {module.module_id: module for module in graph.modules}
    remaining = {module.module_id for module in graph.modules}
    ordered: list[ConfigModule] = []

    while remaining:
        ready = [
            module
            for module in graph.modules
            if module.module_id in remaining
            and all(dep not in remaining for dep in module.depends_on)
        ]
        if not ready:
            # Cycles should not block reporting; preserve source order for the rest.
            ready = [module for module in graph.modules if module.module_id in remaining]
        for module in ready:
            if module.module_id in remaining:
                ordered.append(module_by_id[module.module_id])
                remaining.remove(module.module_id)
    return ordered


def _module_from_spec(spec: _ModuleSpec, index: int, vendor: str) -> ConfigModule:
    module_id = f"{index:04d}:{spec.feature}:{spec.start_line}"
    return ConfigModule(
        module_id=module_id,
        feature=spec.feature,
        vendor=vendor,
        start_line=spec.start_line,
        end_line=spec.end_line,
        source_lines=spec.source_lines,
        provides=sorted(spec.provides),
        consumes=sorted(spec.consumes),
        tags=sorted(spec.tags),
        status=spec.status,
        manual_review_reason=spec.manual_review_reason,
    )


def _module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    feature = _normalize_feature(block)
    text = "\n".join(block.lines)
    provides: set[str] = set()
    consumes: set[str] = set()
    tags: set[str] = set()

    if feature == "ospf":
        return _ospf_module_specs_from_block(block)
    if feature == "bgp":
        return _bgp_module_specs_from_block(block)
    if feature == "route":
        return _static_route_module_specs_from_block(block)
    if feature == "route_policy":
        return _route_policy_module_specs_from_block(block)
    if feature == "qos":
        return _qos_module_specs_from_block(block)
    if feature.startswith("management."):
        return _management_module_specs_from_block(block, feature)

    if feature == "device_identity":
        provides.add("device:hostname")
    elif feature == "vlan":
        provides.update(f"vlan:{vlan_id}" for vlan_id in _extract_vlan_ids(text))
    elif feature == "acl":
        acl_name = _extract_acl_identifier(text)
        if acl_name:
            provides.add(f"acl:{acl_name}")
    elif feature.startswith("interface."):
        name = _extract_interface_name(block.lines[0])
        if name:
            provides.add(f"interface:{name}")
            lag_id = _extract_lag_id(name)
            if feature == "interface.lag" and lag_id:
                provides.add(f"lag:{lag_id}")
            vlan_id = _extract_svi_vlan(name)
            if vlan_id:
                tags.add("svi")
                consumes.add(f"vlan:{vlan_id}")
            member_lag_id = _extract_lag_member_ref(text)
            if member_lag_id:
                tags.add("lag-member")
                consumes.add(f"lag:{member_lag_id}")
        if _has_trunk(text):
            tags.add("trunk")
            consumes.update(f"vlan:{vlan_id}" for vlan_id in _extract_interface_vlan_refs(text))
    elif feature == "ospf":
        process_id = _extract_ospf_process(text)
        if process_id:
            provides.add(f"ospf:{process_id}")
    elif feature == "zone":
        zone_name = _extract_zone_name(text)
        if zone_name:
            provides.add(f"zone:{zone_name}")
    elif feature == "address_object":
        address_name = _extract_address_object_name(text)
        if address_name:
            provides.add(f"addr:{address_name}")
    elif feature == "service_object":
        service_name = _extract_service_object_name(text)
        if service_name:
            provides.add(f"svc:{service_name}")
    elif feature == "security_policy":
        policy_name = _extract_policy_name(text)
        if policy_name:
            provides.add(f"policy:{policy_name}")
        consumes.update(_extract_security_policy_refs(text))
    elif feature == "vrf":
        vrf_name = _extract_vrf_name(text)
        if vrf_name:
            provides.add(f"vrf:{vrf_name}")
        tags.update(_extract_vrf_tags(text))

    status = "manual_review" if feature in _MANUAL_REVIEW_FEATURES else "translatable"
    reason = ""
    if status == "manual_review":
        reason = _manual_review_reason(feature, block.lines[0])

    specs = [
        _ModuleSpec(
            feature=feature,
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=_module_source_lines(block, feature),
            provides=provides,
            consumes=consumes,
            tags=tags,
            status=status,
            manual_review_reason=reason,
        )
    ]

    if feature.startswith("interface."):
        specs.extend(_acl_binding_specs_from_interface(block))

    return specs


def _ospf_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    process_id = _extract_ospf_process("\n".join(block.lines))
    process_key = f"ospf:{process_id}" if process_id else "ospf:unknown"
    specs: list[_ModuleSpec] = []
    process_lines = [block.lines[0]]
    area_context = ""

    for offset, raw_line in enumerate(block.lines[1:], 1):
        stripped = raw_line.strip()
        line_no = block.start_line + offset
        if _is_ospf_process_line(stripped):
            process_lines.append(raw_line)
            continue
        if _is_ospf_area_line(stripped) and not _is_ospf_risky_line(stripped):
            area_id = _extract_ospf_area_id(stripped)
            area_key = f"{process_key}:area:{area_id}" if area_id else f"{process_key}:area:unknown"
            area_context = raw_line
            specs.append(
                _ModuleSpec(
                    feature="ospf.area",
                    start_line=line_no,
                    end_line=line_no,
                    source_lines=[raw_line],
                    provides={area_key},
                    consumes={process_key},
                    tags={area_id} if area_id else set(),
                )
            )
            continue
        if _is_ospf_network_line(stripped):
            source_lines = [area_context, raw_line] if area_context and not _is_cisco_ospf_network(stripped) else [raw_line]
            consumes = {process_key}
            if area_context:
                area_id = _extract_ospf_area_id(area_context.strip())
                if area_id:
                    consumes.add(f"{process_key}:area:{area_id}")
            specs.append(
                _ModuleSpec(
                    feature="ospf.network",
                    start_line=line_no,
                    end_line=line_no,
                    source_lines=source_lines,
                    consumes=consumes,
                )
            )
            continue
        if _is_ospf_passive_line(stripped):
            specs.append(
                _ModuleSpec(
                    feature="ospf.passive_interface",
                    start_line=line_no,
                    end_line=line_no,
                    source_lines=[raw_line],
                    consumes={process_key},
                )
            )
            continue

        risky_feature = _ospf_risky_feature(stripped)
        if risky_feature:
            specs.append(
                _ModuleSpec(
                    feature=risky_feature,
                    start_line=line_no,
                    end_line=line_no,
                    source_lines=[raw_line],
                    consumes={process_key},
                    status="manual_review",
                    manual_review_reason=_ospf_manual_review_reason(risky_feature, stripped),
                )
            )
            continue

        specs.append(
            _ModuleSpec(
                feature="ospf.unknown",
                start_line=line_no,
                end_line=line_no,
                source_lines=[raw_line],
                consumes={process_key},
                status="manual_review",
                manual_review_reason=f"OSPF 子命令无法确定等价转换，需要人工复核: {stripped}",
            )
        )

    specs.insert(
        0,
        _ModuleSpec(
            feature="ospf.process",
            start_line=block.start_line,
            end_line=block.start_line + len(process_lines) - 1,
            source_lines=process_lines,
            provides={process_key},
        ),
    )
    return specs


def _bgp_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    asn = _extract_bgp_asn("\n".join(block.lines))
    process_key = f"bgp:{asn}" if asn else "bgp:unknown"
    specs: list[_ModuleSpec] = []
    process_lines = [block.lines[0]]

    for offset, raw_line in enumerate(block.lines[1:], 1):
        stripped = raw_line.strip()
        line_no = block.start_line + offset
        if _is_bgp_process_line(stripped):
            process_lines.append(raw_line)
            continue
        if _is_bgp_neighbor_line(stripped):
            neighbor = _extract_bgp_neighbor(stripped)
            specs.append(
                _ModuleSpec(
                    feature="bgp.neighbor",
                    start_line=line_no,
                    end_line=line_no,
                    source_lines=[raw_line],
                    consumes={process_key},
                    provides={f"{process_key}:neighbor:{neighbor}"} if neighbor else set(),
                )
            )
            continue
        if _is_bgp_network_line(stripped):
            specs.append(
                _ModuleSpec(
                    feature="bgp.network",
                    start_line=line_no,
                    end_line=line_no,
                    source_lines=[raw_line],
                    consumes={process_key},
                )
            )
            continue

        risky_feature = _bgp_risky_feature(stripped)
        if risky_feature:
            specs.append(
                _ModuleSpec(
                    feature=risky_feature,
                    start_line=line_no,
                    end_line=line_no,
                    source_lines=[_redact_bgp_sensitive_line(raw_line)],
                    consumes={process_key},
                    status="manual_review",
                    manual_review_reason=_bgp_manual_review_reason(risky_feature, _redact_bgp_sensitive_line(stripped)),
                )
            )
            continue

        specs.append(
            _ModuleSpec(
                feature="bgp.unknown",
                start_line=line_no,
                end_line=line_no,
                source_lines=[_redact_bgp_sensitive_line(raw_line)],
                consumes={process_key},
                status="manual_review",
                manual_review_reason=f"BGP 子命令无法确定等价转换，需要人工复核: {_redact_bgp_sensitive_line(stripped)}",
            )
        )

    specs.insert(
        0,
        _ModuleSpec(
            feature="bgp.process",
            start_line=block.start_line,
            end_line=block.start_line + len(process_lines) - 1,
            source_lines=process_lines,
            provides={process_key},
        ),
    )
    return specs


def _static_route_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    specs: list[_ModuleSpec] = []
    for offset, raw_line in enumerate(block.lines):
        stripped = raw_line.strip()
        line_no = block.start_line + offset
        route_info = _extract_static_route_info(stripped)
        consumes = set()
        tags = {"routing", "static"}
        if route_info.get("vrf"):
            consumes.add(f"vrf:{route_info['vrf']}")
            tags.add("vrf")
        feature = "static_route.option" if _is_static_route_risky(stripped) else "static_route"
        status = "manual_review" if feature == "static_route.option" else "translatable"
        reason = ""
        if status == "manual_review":
            reason = f"静态路由附加参数可能影响选路或可用性，需要人工复核: {stripped}"
        provides = set()
        if route_info.get("destination"):
            provides.add(f"route:{route_info['destination']}:{route_info.get('mask', '')}:{route_info.get('next_hop', '')}")
        specs.append(
            _ModuleSpec(
                feature=feature,
                start_line=line_no,
                end_line=line_no,
                source_lines=[raw_line],
                provides=provides,
                consumes=consumes,
                tags=tags,
                status=status,
                manual_review_reason=reason,
            )
        )
    return specs


def _route_policy_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    text = "\n".join(block.lines)
    name = _extract_route_policy_name(text)
    consumes = {f"acl:{acl}" for acl in _extract_route_policy_acl_refs(text)}
    return [
        _ModuleSpec(
            feature="route_policy",
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=block.lines,
            provides={f"route-policy:{name}"} if name else set(),
            consumes=consumes,
            tags={"routing", "policy"},
            status="manual_review",
            manual_review_reason="路由策略会影响路由传播和选路，需要人工复核",
        )
    ]


def _qos_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    first = block.lines[0].strip() if block.lines else ""
    text = "\n".join(block.lines)
    feature = "qos"
    provides: set[str] = set()
    consumes: set[str] = set()
    tags = {"qos"}

    classifier = re.match(r"^traffic\s+classifier\s+(\S+)", first, re.IGNORECASE)
    behavior = re.match(r"^traffic\s+behavior\s+(\S+)", first, re.IGNORECASE)
    policy = re.match(r"^traffic\s+policy\s+(\S+)", first, re.IGNORECASE)
    if classifier:
        feature = "qos.classifier"
        provides.add(f"qos-classifier:{classifier.group(1)}")
        consumes.update(f"acl:{acl}" for acl in _extract_qos_acl_refs(text))
    elif behavior:
        feature = "qos.behavior"
        provides.add(f"qos-behavior:{behavior.group(1)}")
    elif policy:
        feature = "qos.policy"
        provides.add(f"qos-policy:{policy.group(1)}")
        consumes.update(_extract_qos_policy_refs(text))

    return [
        _ModuleSpec(
            feature=feature,
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=block.lines,
            provides=provides,
            consumes=consumes,
            tags=tags,
            status="manual_review",
            manual_review_reason="QoS 分类/行为/策略跨厂商语义差异较大，需要人工复核",
        )
    ]


def _management_module_specs_from_block(block: ConfigBlock, feature: str) -> list[_ModuleSpec]:
    status = "manual_review" if feature in {"management.snmp", "management.aaa"} else "translatable"
    source_lines = [_redact_management_sensitive_line(line) for line in block.lines]
    reason = ""
    if status == "manual_review":
        reason = "管理面配置含认证/社区字/权限语义或敏感值，需要人工复核"
    return [
        _ModuleSpec(
            feature=feature,
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=source_lines,
            tags={"management"},
            status=status,
            manual_review_reason=reason,
        )
    ]


def _module_source_lines(block: ConfigBlock, feature: str) -> list[str]:
    if not feature.startswith("interface."):
        return block.lines
    filtered = [block.lines[0]]
    for line in block.lines[1:]:
        if _extract_acl_binding_ref(line):
            continue
        filtered.append(line)
    return filtered


def _acl_binding_specs_from_interface(block: ConfigBlock) -> list[_ModuleSpec]:
    interface_name = _extract_interface_name(block.lines[0])
    if not interface_name:
        return []
    specs: list[_ModuleSpec] = []
    for offset, raw_line in enumerate(block.lines[1:], 1):
        binding = _extract_acl_binding_ref(raw_line)
        if not binding:
            continue
        acl_id, direction = binding
        line_no = block.start_line + offset
        specs.append(
            _ModuleSpec(
                feature="acl_binding",
                start_line=line_no,
                end_line=line_no,
                source_lines=[raw_line],
                consumes={f"interface:{interface_name}", f"acl:{acl_id}"},
                tags={direction},
            )
        )
    return specs


def _attach_dependencies(graph: ModuleGraph) -> None:
    provider_by_key: dict[str, str] = {}
    for module in graph.modules:
        for key in module.provides:
            provider_by_key.setdefault(key, module.module_id)

    seen_edges: set[tuple[str, str, str]] = set()
    for module in graph.modules:
        for key in module.consumes:
            provider_id = provider_by_key.get(key)
            if not provider_id or provider_id == module.module_id:
                continue
            module.depends_on.append(provider_id)
            edge_key = (module.module_id, provider_id, key)
            if edge_key not in seen_edges:
                graph.edges.append(ModuleDependency(from_module=module.module_id, to_module=provider_id, label=key))
                relation = _coupling_relation(module.feature, key)
                coupling = ModuleCoupling(
                    from_module=module.module_id,
                    to_module=provider_id,
                    relation=relation,
                    resource=key,
                )
                graph.couplings.append(coupling)
                module.couplings.append(coupling.to_dict())
                seen_edges.add(edge_key)
        module.depends_on = sorted(set(module.depends_on))


def _normalize_feature(block: ConfigBlock) -> str:
    text = "\n".join(line.strip() for line in block.lines if line.strip())
    first = block.lines[0].strip() if block.lines else ""
    if re.match(r"^(sysname|hostname)\b", first, re.IGNORECASE):
        return "device_identity"
    if re.match(r"^interface\b", first, re.IGNORECASE):
        return _interface_feature(first)
    if re.match(r"^(ospf|router\s+ospf)\b", first, re.IGNORECASE):
        return "ospf"
    if re.match(r"^(bgp|router\s+bgp)\b", first, re.IGNORECASE):
        return "bgp"
    if re.match(r"^(?:route-policy|route-map)\b", first, re.IGNORECASE):
        return "route_policy"
    if re.match(r"^(?:ntp-service|ntp\s+server)\b", first, re.IGNORECASE):
        return "management.ntp"
    if re.match(r"^(?:snmp-agent|snmp-server)\b", first, re.IGNORECASE):
        return "management.snmp"
    if re.match(r"^(?:info-center|logging)\b", first, re.IGNORECASE):
        return "management.logging"
    if re.match(r"^(?:aaa|local-user|radius|radius-server|tacacs|tacacs-server)\b", first, re.IGNORECASE):
        return "management.aaa"
    if re.match(r"^security-zone\s+name\b|^zone\s+name\b|^zone\s+\S+", first, re.IGNORECASE):
        return "zone"
    if re.match(r"^ip\s+address-set\b|^address\s+name\b|^address\s+\S+", first, re.IGNORECASE):
        return "address_object"
    if re.match(r"^ip\s+service-set\b|^service\s+name\b|^service\s+\S+", first, re.IGNORECASE):
        return "service_object"
    if re.match(r"^security-policy\b|^policy\s+name\b|^policy\s+\S+", first, re.IGNORECASE):
        return "security_policy"
    if re.search(r"\bvoice-vlan\b", text, re.IGNORECASE):
        return "unknown"
    return block.feature


def _interface_feature(first_line: str) -> str:
    name = _extract_interface_name(first_line)
    if _extract_svi_vlan(name):
        return "interface.svi"
    if re.match(r"^(?:LoopBack|Loopback)\d+", name, re.IGNORECASE):
        return "interface.loopback"
    if _extract_lag_id(name):
        return "interface.lag"
    if re.match(r"^Tunnel", name, re.IGNORECASE):
        return "interface.tunnel"
    if re.match(r"^NULL|^Null", name, re.IGNORECASE):
        return "interface.null"
    return "interface.physical"


def _coupling_relation(feature: str, resource: str) -> str:
    if feature == "acl_binding" and resource.startswith("acl:"):
        return "binds_acl_to_interface"
    if feature == "acl_binding" and resource.startswith("interface:"):
        return "binds_acl_to_interface"
    if feature == "security_policy":
        return "policy_uses_object"
    if feature == "static_route" and resource.startswith("vrf:"):
        return "route_uses_vrf"
    if feature == "route_policy" and resource.startswith("acl:"):
        return "policy_uses_acl"
    if feature == "qos.classifier" and resource.startswith("acl:"):
        return "qos_classifier_uses_acl"
    if feature == "qos.policy":
        return "qos_policy_uses_part"
    if feature == "interface.physical" and resource.startswith("lag:"):
        return "member_of_lag"
    if feature.startswith("interface.") and resource.startswith("vlan:"):
        return "interface_uses_vlan"
    if feature.startswith("ospf."):
        return "ospf_submodule_uses_process"
    if feature.startswith("bgp."):
        return "bgp_submodule_uses_process"
    return "depends_on"


def _manual_review_reason(feature: str, first_line: str) -> str:
    if feature == "unknown":
        return f"无法确定等价转换，需要人工复核: {first_line.strip()}"
    if feature == "aaa":
        return "认证/授权/账号配置跨厂商语义差异较大，需要人工复核"
    if feature == "qos":
        return "QoS 策略体跨厂商语义差异较大，需要人工复核"
    return "该模块需要人工复核"


def _extract_vlan_ids(text: str) -> list[str]:
    vlan_ids: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        batch_match = re.match(r"^vlan\s+batch\s+(.+)$", line, re.IGNORECASE)
        simple_match = re.match(r"^vlan\s+(.+)$", line, re.IGNORECASE)
        payload = batch_match.group(1) if batch_match else simple_match.group(1) if simple_match else ""
        vlan_ids.extend(_parse_vlan_tokens(payload))
    return _unique(vlan_ids)


def _parse_vlan_tokens(payload: str) -> list[str]:
    if not payload:
        return []
    tokens = re.split(r"[\s,]+", payload.strip())
    result: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.isdigit() and index + 2 < len(tokens) and tokens[index + 1].lower() == "to" and tokens[index + 2].isdigit():
            start = int(token)
            end = int(tokens[index + 2])
            step = 1 if start <= end else -1
            result.extend(str(value) for value in range(start, end + step, step))
            index += 3
            continue
        if token.isdigit():
            result.append(token)
        index += 1
    return result


def _extract_acl_identifier(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    for pattern in (
        r"^acl\s+number\s+(\S+)",
        r"^acl\s+name\s+(\S+)",
        r"^ip\s+access-list\s+\S+\s+(\S+)",
        r"^access-list\s+(\S+)",
    ):
        match = re.match(pattern, first, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_interface_name(first_line: str) -> str:
    match = re.match(r"^interface\s+(.+)$", first_line.strip(), re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _extract_svi_vlan(interface_name: str) -> str:
    match = re.match(r"^(?:Vlanif|Vlan-interface|Vlan)\s*(\d+)$", interface_name, re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_lag_id(interface_name: str) -> str:
    match = re.match(
        r"^(?:Eth-Trunk|Bridge-Aggregation|Port-channel|Port-Channel|PortChannel)\s*(\d+)$",
        interface_name,
        re.IGNORECASE,
    )
    return match.group(1) if match else ""


def _extract_lag_member_ref(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        for pattern in (
            r"^eth-trunk\s+(\d+)",
            r"^port\s+link-aggregation\s+group\s+(\d+)",
            r"^channel-group\s+(\d+)",
        ):
            match = re.match(pattern, stripped, re.IGNORECASE)
            if match:
                return match.group(1)
    return ""


def _has_trunk(text: str) -> bool:
    return bool(
        re.search(r"\b(port\s+link-type\s+trunk|switchport\s+mode\s+trunk|trunkport|trunk)\b", text, re.IGNORECASE)
    )


def _extract_interface_vlan_refs(text: str) -> list[str]:
    vlan_ids: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        for pattern in (
            r"^port\s+trunk\s+(?:allow-pass|permit)\s+vlan\s+(.+)$",
            r"^switchport\s+trunk\s+allowed\s+vlan\s+(.+)$",
            r"^switchport\s+access\s+vlan\s+(.+)$",
            r"^port\s+default\s+vlan\s+(.+)$",
        ):
            match = re.match(pattern, stripped, re.IGNORECASE)
            if match:
                vlan_ids.extend(_parse_vlan_tokens(match.group(1)))
    return _unique(vlan_ids)


def _extract_acl_binding_refs(text: str) -> list[str]:
    refs: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        for pattern in (
            r"^traffic-filter\s+\S+\s+acl\s+(\S+)",
            r"^packet-filter\s+(\S+)\s+\S+",
            r"^ip\s+access-group\s+(\S+)\s+\S+",
        ):
            match = re.match(pattern, stripped, re.IGNORECASE)
            if match:
                refs.append(match.group(1))
    return _unique(refs)


def _extract_acl_binding_ref(line: str) -> Optional[tuple[str, str]]:
    stripped = line.strip()
    patterns = (
        (r"^traffic-filter\s+(inbound|outbound)\s+acl\s+(\S+)", 2, 1),
        (r"^packet-filter\s+(\S+)\s+(inbound|outbound)", 1, 2),
        (r"^ip\s+access-group\s+(\S+)\s+(in|out)", 1, 2),
    )
    for pattern, acl_group, direction_group in patterns:
        match = re.match(pattern, stripped, re.IGNORECASE)
        if match:
            direction = match.group(direction_group).lower()
            direction = "inbound" if direction == "in" else "outbound" if direction == "out" else direction
            return match.group(acl_group), direction
    return None


def _extract_ospf_process(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    match = re.match(r"^(?:ospf|router\s+ospf)\s+(\S+)", first, re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_bgp_asn(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    match = re.match(r"^(?:bgp|router\s+bgp)\s+(\S+)", first, re.IGNORECASE)
    return match.group(1) if match else ""


def _is_bgp_process_line(line: str) -> bool:
    return bool(re.match(r"^(?:bgp\s+)?router-id\b|^ipv4-family\b|^address-family\b", line, re.IGNORECASE))


def _is_bgp_neighbor_line(line: str) -> bool:
    if _bgp_risky_feature(line):
        return False
    return bool(re.match(r"^(?:peer|neighbor)\s+\S+\s+(?:as-number|remote-as)\s+\S+", line, re.IGNORECASE))


def _is_bgp_network_line(line: str) -> bool:
    return bool(re.match(r"^network\s+\S+(?:\s+(?:mask\s+)?\S+)?$", line, re.IGNORECASE))


def _extract_bgp_neighbor(line: str) -> str:
    match = re.match(r"^(?:peer|neighbor)\s+(\S+)", line, re.IGNORECASE)
    return match.group(1) if match else ""


def _bgp_risky_feature(line: str) -> str:
    if re.search(r"\bpassword\b|authentication-key|keychain", line, re.IGNORECASE):
        return "bgp.password"
    if re.search(r"\b(route-policy|route-map|filter-policy|prefix-list|as-path-filter|community-filter)\b", line, re.IGNORECASE):
        return "bgp.policy"
    if re.match(r"^(?:import-route|redistribute|default-route-advertise)\b", line, re.IGNORECASE):
        return "bgp.redistribute"
    if re.search(r"\bcommunity\b|local-preference|med\b|next-hop|update-source|connect-interface", line, re.IGNORECASE):
        return "bgp.attribute"
    return ""


def _bgp_manual_review_reason(feature: str, line: str) -> str:
    reasons = {
        "bgp.password": "BGP 邻居认证密钥不能自动迁移，已脱敏并要求人工复核",
        "bgp.policy": "BGP 路由策略/过滤器会影响路由传播，需要人工复核",
        "bgp.redistribute": "BGP 重分发策略会影响路由传播，需要人工复核",
        "bgp.attribute": "BGP 属性调优可能影响选路，需要人工复核",
    }
    return f"{reasons.get(feature, 'BGP 子命令需要人工复核')}: {line}"


def _redact_bgp_sensitive_line(line: str) -> str:
    return re.sub(r"(\b(?:password|authentication-key|keychain)\b(?:\s+cipher)?\s+)\S+", r"\1<redacted>", line, flags=re.IGNORECASE)


def _extract_static_route_info(line: str) -> dict[str, str]:
    tokens = line.split()
    if len(tokens) < 2:
        return {}
    if len(tokens) >= 6 and tokens[0].lower() == "ip" and tokens[1].lower() == "route-static":
        index = 2
        info: dict[str, str] = {}
        if index < len(tokens) and tokens[index].lower() == "vpn-instance" and index + 1 < len(tokens):
            info["vrf"] = tokens[index + 1]
            index += 2
        if index + 2 < len(tokens):
            info["destination"] = tokens[index]
            info["mask"] = tokens[index + 1]
            info["next_hop"] = tokens[index + 2]
        return info
    if len(tokens) >= 5 and tokens[0].lower() == "ip" and tokens[1].lower() == "route":
        return {"destination": tokens[2], "mask": tokens[3], "next_hop": tokens[4]}
    return {}


def _is_static_route_risky(line: str) -> bool:
    return bool(re.search(r"\b(track|bfd|tag|description|preference|permanent|name)\b", line, re.IGNORECASE))


def _extract_vrf_name(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    for pattern in (
        r"^ip\s+vpn-instance\s+(\S+)",
        r"^vrf\s+definition\s+(\S+)",
    ):
        match = re.match(pattern, first, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_vrf_tags(text: str) -> set[str]:
    tags: set[str] = {"vrf"}
    if re.search(r"\broute-distinguisher\b|^\s*rd\s+", text, re.IGNORECASE | re.MULTILINE):
        tags.add("rd")
    if re.search(r"\b(vpn-target|route-target)\b", text, re.IGNORECASE):
        tags.add("route-target")
    return tags


def _extract_route_policy_name(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    for pattern in (
        r"^route-policy\s+(\S+)",
        r"^route-map\s+(\S+)",
    ):
        match = re.match(pattern, first, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_route_policy_acl_refs(text: str) -> list[str]:
    refs: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        for pattern in (
            r"^if-match\s+acl\s+(\S+)",
            r"^match\s+ip\s+address\s+(\S+)",
        ):
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                refs.append(match.group(1))
    return _unique(refs)


def _extract_qos_acl_refs(text: str) -> list[str]:
    refs: list[str] = []
    for raw_line in text.splitlines():
        match = re.match(r"^\s*if-match\s+acl\s+(\S+)", raw_line, re.IGNORECASE)
        if match:
            refs.append(match.group(1))
    return _unique(refs)


def _extract_qos_policy_refs(text: str) -> set[str]:
    refs: set[str] = set()
    for raw_line in text.splitlines():
        match = re.match(r"^\s*classifier\s+(\S+)\s+behavior\s+(\S+)", raw_line, re.IGNORECASE)
        if match:
            refs.add(f"qos-classifier:{match.group(1)}")
            refs.add(f"qos-behavior:{match.group(2)}")
    return refs


def _redact_management_sensitive_line(line: str) -> str:
    redacted = re.sub(r"(\b(?:password|secret|shared-key|key)\b(?:\s+cipher)?\s+)\S+", r"\1<redacted>", line, flags=re.IGNORECASE)
    redacted = re.sub(r"(\bcommunity\s+(?:read|write)?\s*(?:cipher)?\s*)\S+", r"\1<redacted>", redacted, flags=re.IGNORECASE)
    return redacted


def _is_ospf_process_line(line: str) -> bool:
    return bool(re.match(r"^router-id\b", line, re.IGNORECASE))


def _is_ospf_area_line(line: str) -> bool:
    return bool(re.match(r"^area\s+\S+(?:\s*)$", line, re.IGNORECASE))


def _is_ospf_network_line(line: str) -> bool:
    return bool(re.match(r"^network\s+\S+\s+\S+(?:\s+area\s+\S+)?$", line, re.IGNORECASE))


def _is_cisco_ospf_network(line: str) -> bool:
    return bool(re.search(r"\sarea\s+\S+$", line, re.IGNORECASE))


def _is_ospf_passive_line(line: str) -> bool:
    return bool(re.match(r"^(?:no\s+)?passive-interface\b|^(?:undo\s+)?silent-interface\b", line, re.IGNORECASE))


def _is_ospf_risky_line(line: str) -> bool:
    return bool(_ospf_risky_feature(line))


def _ospf_risky_feature(line: str) -> str:
    if re.search(r"\bauthentication\b|authentication-mode", line, re.IGNORECASE):
        return "ospf.authentication"
    if re.match(r"^(?:import-route|redistribute|default-route-advertise)\b", line, re.IGNORECASE):
        return "ospf.redistribute"
    if re.search(r"\b(stub|nssa|virtual-link)\b", line, re.IGNORECASE):
        return "ospf.area_special"
    if re.search(r"\bcost\b|message-digest-key", line, re.IGNORECASE):
        return "ospf.interface_tuning"
    return ""


def _ospf_manual_review_reason(feature: str, line: str) -> str:
    reasons = {
        "ospf.authentication": "OSPF 认证跨厂商密钥/算法语义不同，需要人工复核",
        "ospf.redistribute": "OSPF 重分发策略会影响路由传播，需要人工复核",
        "ospf.area_special": "OSPF stub/nssa/virtual-link 区域语义复杂，需要人工复核",
        "ospf.interface_tuning": "OSPF 接口调优参数可能影响收敛/选路，需要人工复核",
    }
    return f"{reasons.get(feature, 'OSPF 子命令需要人工复核')}: {line}"


def _extract_ospf_area_id(line: str) -> str:
    match = re.match(r"^area\s+(\S+)", line, re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_zone_name(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    for pattern in (
        r"^security-zone\s+name\s+(\S+)",
        r"^zone\s+name\s+(\S+)",
        r"^zone\s+(\S+)",
    ):
        match = re.match(pattern, first, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_address_object_name(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    for pattern in (
        r"^ip\s+address-set\s+(\S+)",
        r"^address\s+name\s+(\S+)",
        r"^address\s+(\S+)",
    ):
        match = re.match(pattern, first, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_service_object_name(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    for pattern in (
        r"^ip\s+service-set\s+(\S+)",
        r"^service\s+name\s+(\S+)",
        r"^service\s+(\S+)",
    ):
        match = re.match(pattern, first, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_policy_name(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        for pattern in (
            r"^rule\s+name\s+(\S+)",
            r"^policy\s+name\s+(\S+)",
            r"^policy\s+(\S+)",
        ):
            match = re.match(pattern, stripped, re.IGNORECASE)
            if match:
                return match.group(1)
    return ""


def _extract_security_policy_refs(text: str) -> set[str]:
    refs: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        for pattern in (r"^(?:source-zone|destination-zone)\s+(\S+)",):
            match = re.match(pattern, stripped, re.IGNORECASE)
            if match:
                refs.add(f"zone:{match.group(1)}")
        for pattern in (r"^(?:source-address|destination-address)\s+(\S+)",):
            match = re.match(pattern, stripped, re.IGNORECASE)
            if match and match.group(1).lower() != "any":
                refs.add(f"addr:{match.group(1)}")
        match = re.match(r"^service\s+(\S+)", stripped, re.IGNORECASE)
        if match and match.group(1).lower() != "any":
            refs.add(f"svc:{match.group(1)}")

        inline = re.match(
            r"^policy\s+\S+\s+from\s+(\S+)\s+to\s+(\S+)(?:\s+source\s+(\S+))?(?:\s+destination\s+(\S+))?(?:\s+service\s+(\S+))?",
            stripped,
            re.IGNORECASE,
        )
        if inline:
            refs.add(f"zone:{inline.group(1)}")
            refs.add(f"zone:{inline.group(2)}")
            if inline.group(3) and inline.group(3).lower() != "any":
                refs.add(f"addr:{inline.group(3)}")
            if inline.group(4) and inline.group(4).lower() != "any":
                refs.add(f"addr:{inline.group(4)}")
            if inline.group(5) and inline.group(5).lower() != "any":
                refs.add(f"svc:{inline.group(5)}")
    return refs


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result
