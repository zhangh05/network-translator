from __future__ import annotations

import re

from core.module_graph.models import ConfigModule, ModuleDependency, ModuleGraph
from core.parser.block_splitter import ConfigBlock, split_config_by_feature


_MANUAL_REVIEW_FEATURES = {"unknown", "aaa", "qos"}


def build_module_graph(config_text: str, vendor: str = "unknown") -> ModuleGraph:
    """Build an auditable module graph from source config text.

    The graph is intentionally a decomposition layer, not a translation engine.
    It records which source blocks provide or consume named resources so later
    translation can work module-by-module without silently dropping couplings.
    """

    modules = [_module_from_block(block, index, vendor or "unknown") for index, block in enumerate(split_config_by_feature(config_text, vendor), 1)]
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


def _module_from_block(block: ConfigBlock, index: int, vendor: str) -> ConfigModule:
    feature = _normalize_feature(block)
    module_id = f"{index:04d}:{feature}:{block.start_line}"
    text = "\n".join(block.lines)
    provides: set[str] = set()
    consumes: set[str] = set()
    tags: set[str] = set()

    if feature == "vlan":
        provides.update(f"vlan:{vlan_id}" for vlan_id in _extract_vlan_ids(text))
    elif feature == "acl":
        acl_name = _extract_acl_identifier(text)
        if acl_name:
            provides.add(f"acl:{acl_name}")
    elif feature == "interface":
        name = _extract_interface_name(block.lines[0])
        if name:
            provides.add(f"interface:{name}")
            vlan_id = _extract_svi_vlan(name)
            if vlan_id:
                tags.add("svi")
                consumes.add(f"vlan:{vlan_id}")
        if _has_trunk(text):
            tags.add("trunk")
            consumes.update(f"vlan:{vlan_id}" for vlan_id in _extract_interface_vlan_refs(text))
        consumes.update(f"acl:{acl_id}" for acl_id in _extract_acl_binding_refs(text))
    elif feature == "ospf":
        process_id = _extract_ospf_process(text)
        if process_id:
            provides.add(f"ospf:{process_id}")
    elif feature == "route":
        tags.add("routing")

    status = "manual_review" if feature in _MANUAL_REVIEW_FEATURES else "translatable"
    reason = ""
    if status == "manual_review":
        reason = _manual_review_reason(feature, block.lines[0])

    return ConfigModule(
        module_id=module_id,
        feature=feature,
        vendor=vendor,
        start_line=block.start_line,
        end_line=block.end_line,
        source_lines=block.lines,
        provides=sorted(provides),
        consumes=sorted(consumes),
        tags=sorted(tags),
        status=status,
        manual_review_reason=reason,
    )


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
                seen_edges.add(edge_key)
        module.depends_on = sorted(set(module.depends_on))


def _normalize_feature(block: ConfigBlock) -> str:
    text = "\n".join(line.strip() for line in block.lines if line.strip())
    first = block.lines[0].strip() if block.lines else ""
    if re.match(r"^(ospf|router\s+ospf)\b", first, re.IGNORECASE):
        return "ospf"
    if re.match(r"^(bgp|router\s+bgp)\b", first, re.IGNORECASE):
        return "bgp"
    if re.search(r"\bvoice-vlan\b", text, re.IGNORECASE):
        return "unknown"
    return block.feature


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


def _extract_ospf_process(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    match = re.match(r"^(?:ospf|router\s+ospf)\s+(\S+)", first, re.IGNORECASE)
    return match.group(1) if match else ""


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result
