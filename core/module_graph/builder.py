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
    elif feature == "route":
        tags.add("routing")

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
    if feature == "interface.physical" and resource.startswith("lag:"):
        return "member_of_lag"
    if feature.startswith("interface.") and resource.startswith("vlan:"):
        return "interface_uses_vlan"
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
