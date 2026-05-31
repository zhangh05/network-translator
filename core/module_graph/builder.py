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
    if feature == "rip":
        return _rip_module_specs_from_block(block)
    if feature == "isis":
        return _isis_module_specs_from_block(block)
    if feature == "route":
        return _static_route_module_specs_from_block(block)
    if feature == "route_filter":
        return _route_filter_module_specs_from_block(block)
    if feature == "route_policy":
        return _route_policy_module_specs_from_block(block)
    if feature == "pbr":
        return _pbr_policy_module_specs_from_block(block)
    if feature == "multicast":
        return _multicast_module_specs_from_block(block)
    if feature == "firewall_nat":
        return _firewall_nat_module_specs_from_block(block)
    if feature == "firewall_ipsec":
        return _firewall_ipsec_module_specs_from_block(block)
    if feature == "firewall_profile":
        return _firewall_profile_module_specs_from_block(block)
    if feature == "time_range":
        return _time_range_module_specs_from_block(block)
    if feature == "qos":
        return _qos_module_specs_from_block(block)
    if feature.startswith("l2."):
        return _l2_manual_review_module_specs_from_block(block, feature)
    if feature == "stp.mstp":
        return _l2_manual_review_module_specs_from_block(block, feature)
    if feature.startswith(("platform.", "overlay.")) or feature in {
        "mpls",
        "nqa",
        "ip_sla",
        "firewall.session",
        "firewall.logging",
        "ipv6.static_route",
        "ospfv3.process",
        "ipv6.acl",
        "dhcp.relay",
        "eigrp",
    }:
        return _generic_manual_review_module_specs_from_block(block, feature)
    if feature == "bfd":
        return _bfd_module_specs_from_block(block)
    if feature == "dhcp.pool":
        return _dhcp_pool_module_specs_from_block(block)
    if feature.startswith("management."):
        return _management_module_specs_from_block(block, feature)
    if feature == "object_group":
        return _object_group_module_specs_from_block(block)

    if feature == "device_identity":
        provides.add("device:hostname")
    elif feature == "vlan":
        provides.update(f"vlan:{vlan_id}" for vlan_id in _extract_vlan_ids(text))
    elif feature == "acl":
        acl_name = _extract_acl_identifier(text)
        if acl_name:
            provides.add(f"acl:{acl_name}")
        consumes.update(_extract_acl_refs(text))
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
        if feature == "interface.tunnel" and name:
            provides.add(f"tunnel:{name}")
            consumes.update(_extract_tunnel_endpoint_refs(text))
            tags.update(_extract_tunnel_tags(text))
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

    status = "manual_review" if feature in _MANUAL_REVIEW_FEATURES or feature == "interface.tunnel" else "translatable"
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
        specs.extend(_vrrp_specs_from_interface(block))
        specs.extend(_pbr_binding_specs_from_interface(block))
        specs.extend(_qos_binding_specs_from_interface(block))
        specs.extend(_multicast_specs_from_interface(block))

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
            consumes = {process_key}
            consumes.update(_extract_bgp_policy_refs(stripped))
            specs.append(
                _ModuleSpec(
                    feature=risky_feature,
                    start_line=line_no,
                    end_line=line_no,
                    source_lines=[_redact_bgp_sensitive_line(raw_line)],
                    consumes=consumes,
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


def _rip_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    process_id = _extract_rip_process("\n".join(block.lines))
    process_key = f"rip:{process_id}" if process_id else "rip:default"
    specs = [
        _ModuleSpec(
            feature="rip.process",
            start_line=block.start_line,
            end_line=block.start_line,
            source_lines=[block.lines[0]],
            provides={process_key},
            tags={"routing", "rip"},
            status="manual_review",
            manual_review_reason="RIP 版本、度量、认证和网络声明跨厂商语义需要人工复核",
        )
    ]

    for offset, raw_line in enumerate(block.lines[1:], 1):
        stripped = raw_line.strip()
        line_no = block.start_line + offset
        if re.match(r"^network\s+\S+", stripped, re.IGNORECASE):
            specs.append(
                _ModuleSpec(
                    feature="rip.network",
                    start_line=line_no,
                    end_line=line_no,
                    source_lines=[raw_line],
                    consumes={process_key},
                    tags={"routing", "rip"},
                    status="manual_review",
                    manual_review_reason="RIP network 声明可能受版本、自动汇总和接口范围影响，需要人工复核",
                )
            )
            continue
        feature = "rip.redistribute" if re.match(r"^(?:redistribute|import-route)\b", stripped, re.IGNORECASE) else "rip.unknown"
        specs.append(
            _ModuleSpec(
                feature=feature,
                start_line=line_no,
                end_line=line_no,
                source_lines=[raw_line],
                consumes={process_key},
                tags={"routing", "rip"},
                status="manual_review",
                manual_review_reason=f"RIP 子命令无法确定等价转换，需要人工复核: {stripped}",
            )
        )
    return specs


def _isis_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    process_id = _extract_isis_process("\n".join(block.lines))
    process_key = f"isis:{process_id}" if process_id else "isis:default"
    specs = [
        _ModuleSpec(
            feature="isis.process",
            start_line=block.start_line,
            end_line=block.start_line,
            source_lines=[block.lines[0]],
            provides={process_key},
            tags={"routing", "isis"},
            status="manual_review",
            manual_review_reason="IS-IS 进程、Level、NET、认证和度量语义复杂，需要人工复核",
        )
    ]

    for offset, raw_line in enumerate(block.lines[1:], 1):
        stripped = raw_line.strip()
        line_no = block.start_line + offset
        if re.match(r"^network-entity\s+\S+", stripped, re.IGNORECASE):
            feature = "isis.network_entity"
            reason = "IS-IS network-entity/NET 需要按目标平台格式人工确认"
        elif re.match(r"^(?:import-route|redistribute)\b", stripped, re.IGNORECASE):
            feature = "isis.redistribute"
            reason = "IS-IS 重分发会影响路由传播，需要人工复核"
        elif re.search(r"\b(cost-style|circuit-type|level-|authentication|metric)\b", stripped, re.IGNORECASE):
            feature = "isis.interface_tuning"
            reason = "IS-IS 度量、Level 或认证调优需要人工复核"
        else:
            feature = "isis.unknown"
            reason = f"IS-IS 子命令无法确定等价转换，需要人工复核: {stripped}"
        specs.append(
            _ModuleSpec(
                feature=feature,
                start_line=line_no,
                end_line=line_no,
                source_lines=[raw_line],
                consumes={process_key},
                tags={"routing", "isis"},
                status="manual_review",
                manual_review_reason=reason,
            )
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
    consumes.update(f"route-filter:{name}" for name in _extract_route_policy_filter_refs(text))
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


def _route_filter_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    text = "\n".join(block.lines)
    name = _extract_route_filter_name(text)
    tags = {"routing", "filter"}
    if re.search(r"\bprefix\b|ip-prefix", text, re.IGNORECASE):
        tags.add("prefix")
    if re.search(r"\bas-path\b", text, re.IGNORECASE):
        tags.add("as-path")
    if re.search(r"\bcommunity\b", text, re.IGNORECASE):
        tags.add("community")
    return [
        _ModuleSpec(
            feature="route_filter",
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=block.lines,
            provides={f"route-filter:{name}"} if name else set(),
            tags=tags,
            status="manual_review",
            manual_review_reason="路由过滤器会影响路由匹配和传播范围，需要人工复核",
        )
    ]


def _pbr_policy_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    name = _extract_pbr_policy_name("\n".join(block.lines))
    return [
        _ModuleSpec(
            feature="pbr.policy",
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=block.lines,
            provides={f"pbr:{name}"} if name else set(),
            tags={"routing", "pbr"},
            status="manual_review",
            manual_review_reason="PBR 策略会改变转发路径和下一跳选择，需要人工复核",
        )
    ]


def _multicast_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    tags = {"routing", "multicast"}
    tags.update(_extract_multicast_tags("\n".join(block.lines)))
    return [
        _ModuleSpec(
            feature="multicast",
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=block.lines,
            tags=tags,
            status="manual_review",
            manual_review_reason="组播/PIM/IGMP 配置依赖 RP、接口、ASM/SSM 和平台模式，需要人工复核",
        )
    ]


def _firewall_nat_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    text = "\n".join(block.lines)
    name = _extract_nat_policy_name(text)
    return [
        _ModuleSpec(
            feature="firewall.nat",
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=block.lines,
            provides={f"nat-policy:{name}"} if name else set(),
            consumes=_extract_security_policy_refs(text),
            tags={"firewall", "nat"},
            status="manual_review",
            manual_review_reason="NAT/source-nat/destination-nat 会改变地址转换和会话行为，跨厂商必须人工复核",
        )
    ]


def _firewall_ipsec_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    text = "\n".join(block.lines)
    name = _extract_ipsec_name(text)
    provides = {name} if name else set()
    return [
        _ModuleSpec(
            feature="firewall.ipsec",
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=[_redact_ipsec_sensitive_line(line) for line in block.lines],
            provides=provides,
            consumes=_extract_ipsec_refs(text),
            tags={"firewall", "ipsec", "vpn"},
            status="manual_review",
            manual_review_reason="IPsec/IKE/VPN 参数、密钥、提议、ACL 和 peer 关系跨厂商语义复杂，需要人工复核",
        )
    ]


def _firewall_profile_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    text = "\n".join(block.lines)
    profile_name = _extract_firewall_profile_name(text)
    return [
        _ModuleSpec(
            feature="firewall.profile",
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=block.lines,
            provides={f"profile:{profile_name}"} if profile_name else set(),
            tags=_extract_firewall_profile_tags(text),
            status="manual_review",
            manual_review_reason="URL/AV/IPS/application/user/profile 等安全能力依赖目标平台特征库和动作语义，需要人工复核",
        )
    ]


def _time_range_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    name = _extract_time_range_name(block.lines[0] if block.lines else "")
    return [
        _ModuleSpec(
            feature="time_range",
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=block.lines,
            provides={f"time-range:{name}"} if name else set(),
            tags={"time-range"},
            status="manual_review",
            manual_review_reason="时间范围/调度语义和引用点跨厂商差异较大，需要人工复核",
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
    cisco_policy = re.match(r"^policy-map\s+(\S+)", first, re.IGNORECASE)
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
    elif cisco_policy:
        feature = "qos.policy"
        provides.add(f"qos-policy:{cisco_policy.group(1)}")

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


def _l2_manual_review_module_specs_from_block(block: ConfigBlock, feature: str) -> list[_ModuleSpec]:
    reason_by_feature = {
        "l2.qinq": "QinQ/VLAN stacking/VLAN mapping 会改变二层标签封装和透传边界，需要人工复核",
        "l2.voice_vlan": "Voice VLAN 的 OUI、LLDP/CDP 联动和接入行为跨厂商差异较大，需要人工复核",
        "l2.lldp": "LLDP/CDP 邻居发现、TLV、MED/voice 等语义跨厂商不同，需要人工复核",
        "l2.mac_table": "静态 MAC、黑洞 MAC、动态学习限制等二层转发表行为需要人工复核",
        "l2.dhcp_snooping": "DHCP Snooping 会影响绑定表、信任口和下游安全能力，需要人工复核",
        "l2.source_guard": "IP Source Guard/用户绑定依赖 DHCP Snooping 或静态绑定表，需要人工复核",
        "l2.arp_security": "ARP inspection/anti-attack 依赖绑定表、VLAN 和信任口语义，需要人工复核",
        "l2.port_security": "端口安全会影响 MAC 学习、违规动作和接入口行为，需要人工复核",
        "l2.storm_control": "风暴抑制阈值单位和动作跨厂商差异较大，需要人工复核",
        "l2.poe": "PoE 供电功率、优先级、检测模式和故障动作跨厂商差异较大，需要人工复核",
        "l2.loop_detection": "环路检测/Loopback Detection 会影响端口阻断和告警动作，需要人工复核",
        "stp.mstp": "MSTP region、instance 与 VLAN 映射会影响生成树拓扑，需要人工复核",
    }
    tag = feature.split(".", 1)[-1] if "." in feature else feature
    return [
        _ModuleSpec(
            feature=feature,
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=block.lines,
            tags={"l2", tag},
            status="manual_review",
            manual_review_reason=reason_by_feature.get(feature, "二层高级特性跨厂商语义不确定，需要人工复核"),
        )
    ]


def _generic_manual_review_module_specs_from_block(block: ConfigBlock, feature: str) -> list[_ModuleSpec]:
    reason_by_feature = {
        "platform.stack": "堆叠/虚拟化会影响设备角色、成员链路、接口编号和升级方式，需要人工复核",
        "overlay.vxlan": "VXLAN VNI、隧道端点和二三层网关语义跨厂商差异较大，需要人工复核",
        "overlay.evpn": "EVPN 控制平面、RT/RD 和邻居能力需要按目标平台设计确认",
        "mpls": "MPLS/LDP/TE/VPN 标签转发和控制平面语义复杂，需要人工复核",
        "nqa": "NQA/IP SLA 探测对象、频率、联动动作和告警语义需要人工复核",
        "ip_sla": "NQA/IP SLA 探测对象、频率、联动动作和告警语义需要人工复核",
        "firewall.session": "会话超时、连接限制和状态表行为会影响业务连接，需要人工复核",
        "firewall.logging": "日志/审计策略涉及级别、目的地、策略命中和合规要求，需要人工复核",
        "ipv6.static_route": "IPv6 静态路由前缀、下一跳和 VRF 语义需要人工复核",
        "ospfv3.process": "OSPFv3/IPv6 OSPF 的进程、接口绑定、认证和区域语义需要人工复核",
        "ipv6.acl": "IPv6 ACL 的协议、扩展头、端口和绑定语义需要人工复核",
        "dhcp.relay": "DHCP Relay/helper 地址和接口绑定行为跨厂商不同，需要人工复核",
        "eigrp": "EIGRP 是 Cisco 特有路由协议，迁移到非 Cisco 平台必须重新设计或人工确认",
    }
    tag = feature.split(".", 1)[-1] if "." in feature else feature
    return [
        _ModuleSpec(
            feature=feature,
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=block.lines,
            tags={tag},
            status="manual_review",
            manual_review_reason=reason_by_feature.get(feature, "该产品能力跨厂商语义不确定，需要人工复核"),
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


def _bfd_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    text = "\n".join(block.lines)
    name = _extract_bfd_name(block.lines[0] if block.lines else "")
    consumes = _extract_bfd_endpoint_refs(text)
    return [
        _ModuleSpec(
            feature="bfd.session",
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=block.lines,
            provides={f"bfd:{name}"} if name else set(),
            consumes=consumes,
            tags={"bfd"},
            status="manual_review",
            manual_review_reason="bfd session 跨厂商检测间隔、会话绑定和联动语义需要人工复核",
        )
    ]


def _dhcp_pool_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    text = "\n".join(block.lines)
    pool_name = _extract_dhcp_pool_name(block.lines[0] if block.lines else "")
    provides: set[str] = set()
    consumes: set[str] = set()
    if pool_name:
        provides.add(f"dhcp-pool:{pool_name}")
    subnet = _extract_dhcp_subnet(text)
    if subnet:
        provides.add(f"subnet:{subnet}")
    gateway = _extract_dhcp_gateway(text)
    if gateway:
        consumes.add(f"gateway:{gateway}")
    return [
        _ModuleSpec(
            feature="dhcp.pool",
            start_line=block.start_line,
            end_line=block.end_line,
            source_lines=block.lines,
            provides=provides,
            consumes=consumes,
            tags={"dhcp"},
            status="manual_review",
            manual_review_reason="DHCP 地址池、网关、DNS、租期与排除地址跨厂商语义需要人工复核",
        )
    ]


def _object_group_module_specs_from_block(block: ConfigBlock) -> list[_ModuleSpec]:
    name = _extract_object_group_name("\n".join(block.lines))
    group_key = f"object-group:{name}" if name else ""
    tags = _extract_object_group_tags(block.lines[0] if block.lines else "")
    specs = [
        _ModuleSpec(
            feature="object_group",
            start_line=block.start_line,
            end_line=block.start_line,
            source_lines=[block.lines[0]] if block.lines else [],
            provides={group_key} if group_key else set(),
            tags=tags,
            status="manual_review",
            manual_review_reason="对象组成员和跨厂商对象语义需要人工复核",
        )
    ]

    for offset, raw_line in enumerate(block.lines[1:], 1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        line_no = block.start_line + offset
        specs.append(
            _ModuleSpec(
                feature="object_group.member",
                start_line=line_no,
                end_line=line_no,
                source_lines=[raw_line],
                consumes={group_key} if group_key else set(),
                tags=tags.union(_extract_object_group_member_tags(stripped)),
                status="manual_review",
                manual_review_reason="对象组成员需要确认目标平台对象类型、端口范围和引用语义",
            )
        )
    return specs


def _module_source_lines(block: ConfigBlock, feature: str) -> list[str]:
    if not feature.startswith("interface."):
        return block.lines
    filtered = [block.lines[0]]
    for line in block.lines[1:]:
        if (
            _extract_acl_binding_ref(line)
            or _extract_fhrp_ref(line)
            or _extract_pbr_binding_ref(line)
            or _extract_qos_binding_ref(line)
            or _is_interface_multicast_line(line)
        ):
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


def _vrrp_specs_from_interface(block: ConfigBlock) -> list[_ModuleSpec]:
    interface_name = _extract_interface_name(block.lines[0])
    if not interface_name:
        return []
    by_group: dict[tuple[str, str], list[tuple[int, str]]] = {}
    for offset, raw_line in enumerate(block.lines[1:], 1):
        fhrp = _extract_fhrp_ref(raw_line)
        if not fhrp:
            continue
        protocol, group_id = fhrp
        by_group.setdefault((protocol, group_id), []).append((block.start_line + offset, raw_line))

    specs: list[_ModuleSpec] = []
    for (protocol, group_id), entries in by_group.items():
        line_numbers = [line_no for line_no, _ in entries]
        source_lines = [line for _, line in entries]
        specs.append(
            _ModuleSpec(
                feature=f"fhrp.{protocol}",
                start_line=min(line_numbers),
                end_line=max(line_numbers),
                source_lines=source_lines,
                provides={f"{protocol}:{interface_name}:{group_id}"},
                consumes={f"interface:{interface_name}"},
                tags={"fhrp", protocol, f"group:{group_id}"},
                status="manual_review",
                manual_review_reason="FHRP/VRRP/HSRP 的 VIP、优先级、抢占和 track 行为跨厂商差异较大，需要人工复核",
            )
        )
    return specs


def _pbr_binding_specs_from_interface(block: ConfigBlock) -> list[_ModuleSpec]:
    interface_name = _extract_interface_name(block.lines[0])
    if not interface_name:
        return []
    specs: list[_ModuleSpec] = []
    for offset, raw_line in enumerate(block.lines[1:], 1):
        policy_name = _extract_pbr_binding_ref(raw_line)
        if not policy_name:
            continue
        line_no = block.start_line + offset
        specs.append(
            _ModuleSpec(
                feature="pbr.binding",
                start_line=line_no,
                end_line=line_no,
                source_lines=[raw_line],
                consumes={f"interface:{interface_name}", f"route-policy:{policy_name}"},
                tags={"routing", "pbr"},
                status="manual_review",
                manual_review_reason="接口 PBR 绑定会改变该接口入方向转发路径，需要人工复核",
            )
        )
    return specs


def _qos_binding_specs_from_interface(block: ConfigBlock) -> list[_ModuleSpec]:
    interface_name = _extract_interface_name(block.lines[0])
    if not interface_name:
        return []
    specs: list[_ModuleSpec] = []
    for offset, raw_line in enumerate(block.lines[1:], 1):
        binding = _extract_qos_binding_ref(raw_line)
        if not binding:
            continue
        policy_name, direction = binding
        line_no = block.start_line + offset
        specs.append(
            _ModuleSpec(
                feature="qos.binding",
                start_line=line_no,
                end_line=line_no,
                source_lines=[raw_line],
                consumes={f"interface:{interface_name}", f"qos-policy:{policy_name}"},
                tags={"qos", direction},
                status="manual_review",
                manual_review_reason="接口 QoS 策略绑定会影响流量分类、限速和队列行为，需要人工复核",
            )
        )
    return specs


def _multicast_specs_from_interface(block: ConfigBlock) -> list[_ModuleSpec]:
    interface_name = _extract_interface_name(block.lines[0])
    if not interface_name:
        return []
    entries: list[tuple[int, str]] = []
    for offset, raw_line in enumerate(block.lines[1:], 1):
        if _is_interface_multicast_line(raw_line):
            entries.append((block.start_line + offset, raw_line))
    if not entries:
        return []
    line_numbers = [line_no for line_no, _ in entries]
    source_lines = [line for _, line in entries]
    tags = {"routing", "multicast"}
    tags.update(_extract_multicast_tags("\n".join(source_lines)))
    return [
        _ModuleSpec(
            feature="multicast.interface",
            start_line=min(line_numbers),
            end_line=max(line_numbers),
            source_lines=source_lines,
            consumes={f"interface:{interface_name}"},
            tags=tags,
            status="manual_review",
            manual_review_reason="接口组播/PIM/IGMP 行为依赖组播域、RP 和接口模式，需要人工复核",
        )
    ]


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
        if re.search(r"\b(qinq|dot1q-tunnel|vlan-stacking)\b", text, re.IGNORECASE):
            return "l2.qinq"
        return _interface_feature(first)
    if re.match(r"^(?:voice-vlan|voice\s+vlan)\b", first, re.IGNORECASE):
        return "l2.voice_vlan"
    if re.match(r"^(?:poe|power\s+inline)\b", first, re.IGNORECASE):
        return "l2.poe"
    if re.match(r"^(?:loopback-detection|loop-detect|loopback\s+detect)\b", first, re.IGNORECASE):
        return "l2.loop_detection"
    if re.match(r"^dhcp\s+snooping\b", first, re.IGNORECASE):
        return "l2.dhcp_snooping"
    if re.match(r"^(?:ip\s+source\s+check|ip\s+source\s+guard)\b", first, re.IGNORECASE):
        return "l2.source_guard"
    if re.match(r"^arp\s+(?:anti-attack|inspection|detection|check)\b", first, re.IGNORECASE):
        return "l2.arp_security"
    if re.match(r"^port-security\b", first, re.IGNORECASE):
        return "l2.port_security"
    if re.match(r"^(?:storm-control|broadcast-suppression|multicast-suppression|unicast-suppression)\b", first, re.IGNORECASE):
        return "l2.storm_control"
    if re.match(r"^(?:irf|stack|vss|css)\b", first, re.IGNORECASE):
        return "platform.stack"
    if re.match(r"^vxlan\b", first, re.IGNORECASE):
        return "overlay.vxlan"
    if re.match(r"^(?:evpn|evpn-overlay)\b", first, re.IGNORECASE):
        return "overlay.evpn"
    if re.match(r"^(?:lldp|cdp)\b", first, re.IGNORECASE):
        return "l2.lldp"
    if re.match(r"^(?:mac-address|mac\s+address-table)\b", first, re.IGNORECASE):
        return "l2.mac_table"
    if re.match(r"^(ospf|router\s+ospf)\b", first, re.IGNORECASE):
        return "ospf"
    if re.match(r"^(bgp|router\s+bgp)\b", first, re.IGNORECASE):
        return "bgp"
    if re.match(r"^(?:rip|router\s+rip)\b", first, re.IGNORECASE):
        return "rip"
    if re.match(r"^(?:ospfv3|router\s+ospfv3|ipv6\s+router\s+ospf)\b", first, re.IGNORECASE):
        return "ospfv3.process"
    if re.match(r"^(?:eigrp|router\s+eigrp)\b", first, re.IGNORECASE):
        return "eigrp"
    if re.match(r"^(?:isis|is-is|router\s+isis|router\s+is-is)\b", first, re.IGNORECASE):
        return "isis"
    if re.match(r"^bfd\b", first, re.IGNORECASE):
        return "bfd"
    if re.match(r"^ipv6\s+(?:route-static|route)\b", first, re.IGNORECASE):
        return "ipv6.static_route"
    if re.match(r"^ipv6\s+access-list\b|^acl\s+ipv6\b", first, re.IGNORECASE):
        return "ipv6.acl"
    if re.match(r"^(?:dhcp\s+relay|ip\s+helper-address|dhcp\s+select\s+relay)\b", first, re.IGNORECASE):
        return "dhcp.relay"
    if re.match(r"^mpls\b", first, re.IGNORECASE):
        return "mpls"
    if re.match(r"^nqa\s+test-instance\b", first, re.IGNORECASE):
        return "nqa"
    if re.match(r"^ip\s+sla\b", first, re.IGNORECASE):
        return "ip_sla"
    if re.match(r"^(?:ip\s+pool|ip\s+dhcp\s+pool)\s+\S+", first, re.IGNORECASE):
        return "dhcp.pool"
    if re.match(r"^(?:route-policy|route-map)\b", first, re.IGNORECASE):
        return "route_policy"
    if re.match(
        r"^(?:ip\s+(?:ip-prefix|prefix-list)|(?:ip\s+)?prefix-list|(?:ip\s+)?as-path-filter|(?:ip\s+)?community-filter)\b",
        first,
        re.IGNORECASE,
    ):
        return "route_filter"
    if re.match(r"^object-group\b", first, re.IGNORECASE):
        return "object_group"
    if re.match(r"^(?:policy-based-route|ip\s+policy-based-route)\b", first, re.IGNORECASE):
        return "pbr"
    if re.match(r"^(?:multicast|pim|igmp|ip\s+multicast-routing)\b", first, re.IGNORECASE):
        return "multicast"
    if re.match(r"^(?:nat-policy|nat\b|source-nat\b|destination-nat\b|ip\s+nat\b)", first, re.IGNORECASE):
        return "firewall_nat"
    if re.match(r"^(?:ike|ipsec|crypto|tunnel-group|vpn)\b", first, re.IGNORECASE):
        return "firewall_ipsec"
    if re.match(r"^time-range\b", first, re.IGNORECASE):
        return "time_range"
    if re.match(r"^(?:url-filter|antivirus|av-profile|intrusion|ips|profile|application|user-profile)\b", first, re.IGNORECASE):
        return "firewall_profile"
    if re.match(r"^session\b", first, re.IGNORECASE):
        return "firewall.session"
    if re.match(r"^(?:traffic\s+log|log\s+setting|security-log|log\b)", first, re.IGNORECASE):
        return "firewall.logging"
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
    if re.match(r"^stp\s+region-configuration\b", first, re.IGNORECASE) or re.search(r"\b(instance\s+\d+\s+vlan|region-name|revision-level)\b", text, re.IGNORECASE):
        return "stp.mstp"
    if re.search(r"\bvoice-vlan\b", text, re.IGNORECASE):
        return "l2.voice_vlan"
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
    if feature == "security_policy" and resource.startswith("time-range:"):
        return "policy_uses_time_range"
    if feature == "security_policy" and resource.startswith("profile:"):
        return "policy_uses_profile"
    if feature == "security_policy":
        return "policy_uses_object"
    if feature == "static_route" and resource.startswith("vrf:"):
        return "route_uses_vrf"
    if feature == "route_policy" and resource.startswith("acl:"):
        return "policy_uses_acl"
    if feature == "route_policy" and resource.startswith("route-filter:"):
        return "policy_uses_route_filter"
    if feature == "acl" and resource.startswith("time-range:"):
        return "acl_uses_time_range"
    if feature == "acl" and resource.startswith("object-group:"):
        return "acl_uses_object_group"
    if feature == "object_group.member" and resource.startswith("object-group:"):
        return "object_group_has_member"
    if feature == "qos.classifier" and resource.startswith("acl:"):
        return "qos_classifier_uses_acl"
    if feature == "qos.policy":
        return "qos_policy_uses_part"
    if feature == "qos.binding":
        return "binds_qos_to_interface" if resource.startswith(("interface:", "qos-policy:")) else "qos_binding_uses_resource"
    if feature == "fhrp.vrrp" and resource.startswith("interface:"):
        return "fhrp_uses_interface"
    if feature == "bfd.session":
        return "bfd_uses_endpoint"
    if feature == "dhcp.pool" and resource.startswith("gateway:"):
        return "dhcp_pool_uses_gateway"
    if feature == "pbr.binding":
        return "pbr_uses_policy" if resource.startswith("route-policy:") else "pbr_uses_interface"
    if feature == "multicast.interface" and resource.startswith("interface:"):
        return "multicast_uses_interface"
    if feature == "firewall.nat":
        return "nat_uses_object"
    if feature == "firewall.ipsec" and resource.startswith("acl:"):
        return "ipsec_uses_acl"
    if feature == "interface.physical" and resource.startswith("lag:"):
        return "member_of_lag"
    if feature.startswith("interface.") and resource.startswith("vlan:"):
        return "interface_uses_vlan"
    if feature.startswith("ospf."):
        return "ospf_submodule_uses_process"
    if feature.startswith("bgp."):
        if resource.startswith("route-policy:"):
            return "bgp_uses_route_policy"
        if resource.startswith("route-filter:"):
            return "bgp_uses_route_filter"
        return "bgp_submodule_uses_process"
    if feature.startswith("rip."):
        return "rip_submodule_uses_process"
    if feature.startswith("isis."):
        return "isis_submodule_uses_process"
    return "depends_on"


def _manual_review_reason(feature: str, first_line: str) -> str:
    if feature == "unknown":
        return f"无法确定等价转换，需要人工复核: {first_line.strip()}"
    if feature == "aaa":
        return "认证/授权/账号配置跨厂商语义差异较大，需要人工复核"
    if feature == "qos":
        return "QoS 策略体跨厂商语义差异较大，需要人工复核"
    if feature == "interface.tunnel":
        return "Tunnel/GRE/IPsec 等隧道接口涉及封装、源/目的、MTU 和路由联动，需要人工复核"
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


def _extract_acl_refs(text: str) -> set[str]:
    refs: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        for pattern in (
            r"\btime-range\s+(\S+)",
            r"\btime\s+(\S+)",
        ):
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                refs.add(f"time-range:{match.group(1)}")
        for pattern in (
            r"\bobject-group\s+(\S+)",
            r"\bsource\s+object-group\s+(\S+)",
            r"\bdestination\s+object-group\s+(\S+)",
        ):
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                refs.add(f"object-group:{match.group(1)}")
    return refs


def _extract_object_group_name(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    match = re.match(r"^object-group\s+(?:network|service|protocol|icmp-type)?\s*(\S+)", first, re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_object_group_tags(first_line: str) -> set[str]:
    tags = {"object-group"}
    lower = first_line.lower()
    if "network" in lower:
        tags.add("network")
    if "service" in lower:
        tags.add("service")
    if "protocol" in lower:
        tags.add("protocol")
    if "icmp" in lower:
        tags.add("icmp")
    return tags


def _extract_object_group_member_tags(line: str) -> set[str]:
    tags: set[str] = set()
    lower = line.lower()
    if "host" in lower or "network-object" in lower:
        tags.add("network")
    if "service-object" in lower or "port-object" in lower or re.search(r"\b(tcp|udp|icmp)\b", lower):
        tags.add("service")
    if "range" in lower:
        tags.add("range")
    return tags


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


def _extract_fhrp_ref(line: str) -> Optional[tuple[str, str]]:
    stripped = line.strip()
    vrrp = re.match(r"^vrrp\s+vrid\s+(\S+)\b", stripped, re.IGNORECASE)
    if vrrp:
        return "vrrp", vrrp.group(1)
    hsrp = re.match(r"^standby\s+(\S+)\b", stripped, re.IGNORECASE)
    if hsrp:
        return "hsrp", hsrp.group(1)
    return None


def _extract_vrrp_ref(line: str) -> str:
    ref = _extract_fhrp_ref(line)
    return ref[1] if ref else ""


def _extract_bfd_name(first_line: str) -> str:
    match = re.match(r"^bfd\s+(\S+)", first_line.strip(), re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_bfd_endpoint_refs(text: str) -> set[str]:
    refs: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        peer = re.search(r"\bpeer-ip\s+(\S+)", stripped, re.IGNORECASE)
        source = re.search(r"\bsource-ip\s+(\S+)", stripped, re.IGNORECASE)
        interface = re.search(r"\binterface\s+(\S+)", stripped, re.IGNORECASE)
        if peer:
            refs.add(f"peer:{peer.group(1)}")
        if source:
            refs.add(f"source:{source.group(1)}")
        if interface:
            refs.add(f"interface:{interface.group(1)}")
    return refs


def _extract_tunnel_endpoint_refs(text: str) -> set[str]:
    refs: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        for keyword, prefix in (("source", "source"), ("destination", "destination"), ("tunnel source", "source"), ("tunnel destination", "destination")):
            match = re.match(rf"^{re.escape(keyword)}\s+(\S+)", stripped, re.IGNORECASE)
            if match:
                refs.add(f"{prefix}:{match.group(1)}")
    return refs


def _extract_tunnel_tags(text: str) -> set[str]:
    tags = {"tunnel"}
    for line in text.splitlines():
        match = re.match(r"^\s*tunnel-protocol\s+(\S+)", line, re.IGNORECASE)
        if match:
            tags.add(match.group(1).lower())
        match = re.match(r"^\s*tunnel\s+mode\s+(\S+)", line, re.IGNORECASE)
        if match:
            tags.add(match.group(1).lower())
    return tags


def _extract_dhcp_pool_name(first_line: str) -> str:
    for pattern in (
        r"^ip\s+pool\s+(\S+)",
        r"^ip\s+dhcp\s+pool\s+(\S+)",
    ):
        match = re.match(pattern, first_line.strip(), re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_dhcp_subnet(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        for pattern in (
            r"^network\s+(\S+)\s+mask\s+(\S+)",
            r"^network\s+(\S+)\s+(\S+)",
        ):
            match = re.match(pattern, stripped, re.IGNORECASE)
            if match:
                return f"{match.group(1)}/{match.group(2)}"
    return ""


def _extract_dhcp_gateway(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        for pattern in (
            r"^gateway-list\s+(\S+)",
            r"^default-router\s+(\S+)",
        ):
            match = re.match(pattern, stripped, re.IGNORECASE)
            if match:
                return match.group(1)
    return ""


def _extract_ospf_process(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    match = re.match(r"^(?:ospf|router\s+ospf)\s+(\S+)", first, re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_bgp_asn(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    match = re.match(r"^(?:bgp|router\s+bgp)\s+(\S+)", first, re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_rip_process(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    match = re.match(r"^rip\s+(\S+)", first, re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_isis_process(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    for pattern in (
        r"^(?:isis|is-is)\s+(\S+)",
        r"^router\s+(?:isis|is-is)\s+(\S+)",
    ):
        match = re.match(pattern, first, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


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
    if re.search(r"\b(route-policy|route-map|filter-policy|prefix-list|ip-prefix|as-path-filter|community-filter)\b", line, re.IGNORECASE):
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


def _extract_bgp_policy_refs(line: str) -> set[str]:
    refs: set[str] = set()
    for pattern in (
        r"\broute-policy\s+(\S+)",
        r"\broute-map\s+(\S+)",
    ):
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            refs.add(f"route-policy:{match.group(1)}")
    for pattern in (
        r"\bip-prefix\s+(\S+)",
        r"\bprefix-list\s+(\S+)",
        r"\bas-path-filter\s+(\S+)",
        r"\bcommunity-filter\s+(\S+)",
    ):
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            refs.add(f"route-filter:{match.group(1)}")
    return refs


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


def _extract_route_policy_filter_refs(text: str) -> list[str]:
    refs: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        for pattern in (
            r"^if-match\s+ip-prefix\s+(\S+)",
            r"^match\s+ip\s+address\s+prefix-list\s+(\S+)",
            r"^if-match\s+as-path-filter\s+(\S+)",
            r"^if-match\s+community-filter\s+(\S+)",
            r"^match\s+as-path\s+(\S+)",
            r"^match\s+community\s+(\S+)",
        ):
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                refs.append(match.group(1))
    return _unique(refs)


def _extract_route_filter_name(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    for pattern in (
        r"^ip\s+ip-prefix\s+(\S+)",
        r"^ip\s+prefix-list\s+(\S+)",
        r"^prefix-list\s+(\S+)",
        r"^(?:ip\s+)?as-path-filter\s+(\S+)",
        r"^(?:ip\s+)?community-filter\s+(\S+)",
    ):
        match = re.match(pattern, first, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_pbr_policy_name(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    for pattern in (
        r"^(?:policy-based-route|ip\s+policy-based-route)\s+(\S+)",
        r"^route-map\s+(\S+)",
    ):
        match = re.match(pattern, first, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_pbr_binding_ref(line: str) -> str:
    stripped = line.strip()
    for pattern in (
        r"^ip\s+policy\s+route-map\s+(\S+)",
        r"^ip\s+policy-based-route\s+(\S+)",
        r"^policy-based-route\s+(\S+)",
    ):
        match = re.match(pattern, stripped, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_qos_binding_ref(line: str) -> Optional[tuple[str, str]]:
    stripped = line.strip()
    patterns = (
        (r"^traffic-policy\s+(\S+)\s+(inbound|outbound)\b", 1, 2),
        (r"^service-policy\s+(input|output)\s+(\S+)\b", 2, 1),
    )
    for pattern, policy_group, direction_group in patterns:
        match = re.match(pattern, stripped, re.IGNORECASE)
        if not match:
            continue
        direction = match.group(direction_group).lower()
        direction = "inbound" if direction == "input" else "outbound" if direction == "output" else direction
        return match.group(policy_group), direction
    return None


def _is_interface_multicast_line(line: str) -> bool:
    stripped = line.strip()
    return bool(
        re.match(
            r"^(?:ip\s+pim\b|pim\b|igmp\b|ip\s+igmp\b|multicast\b)",
            stripped,
            re.IGNORECASE,
        )
    )


def _extract_multicast_tags(text: str) -> set[str]:
    tags: set[str] = set()
    if re.search(r"\bpim\b", text, re.IGNORECASE):
        tags.add("pim")
    if re.search(r"\bigmp\b", text, re.IGNORECASE):
        tags.add("igmp")
    if re.search(r"\bmulticast\b", text, re.IGNORECASE):
        tags.add("multicast")
    if re.search(r"\brp-address\b|bsr|ssm|sparse-mode|dense-mode", text, re.IGNORECASE):
        tags.add("control-plane")
    return tags


def _extract_nat_policy_name(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        for pattern in (
            r"^rule\s+name\s+(\S+)",
            r"^nat-policy\s+(\S+)",
            r"^policy\s+name\s+(\S+)",
            r"^policy\s+(\S+)",
        ):
            match = re.match(pattern, stripped, re.IGNORECASE)
            if match:
                return match.group(1)
    return ""


def _extract_ipsec_name(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    patterns = (
        (r"^ike\s+proposal\s+(\S+)", "ike-proposal"),
        (r"^ike\s+peer\s+(\S+)", "ike-peer"),
        (r"^ipsec\s+proposal\s+(\S+)", "ipsec-proposal"),
        (r"^ipsec\s+policy\s+(\S+)\s+(\S+)", "ipsec-policy"),
        (r"^ipsec\s+profile\s+(\S+)", "ipsec-profile"),
        (r"^crypto\s+isakmp\s+policy\s+(\S+)", "crypto-isakmp-policy"),
        (r"^crypto\s+ipsec\s+transform-set\s+(\S+)", "crypto-transform-set"),
        (r"^crypto\s+map\s+(\S+)\s+(\S+)", "crypto-map"),
        (r"^crypto\s+ipsec\s+profile\s+(\S+)", "crypto-ipsec-profile"),
        (r"^tunnel-group\s+(\S+)", "tunnel-group"),
    )
    for pattern, prefix in patterns:
        match = re.match(pattern, first, re.IGNORECASE)
        if not match:
            continue
        if prefix in {"ipsec-policy", "crypto-map"} and len(match.groups()) >= 2:
            return f"{prefix}:{match.group(1)}:{match.group(2)}"
        return f"{prefix}:{match.group(1)}"
    return ""


def _extract_ipsec_refs(text: str) -> set[str]:
    refs: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        for pattern, prefix in (
            (r"^(?:security\s+acl|match\s+address)\s+(\S+)", "acl"),
            (r"^ike-peer\s+(\S+)", "ike-peer"),
            (r"^ike-proposal\s+(\S+)", "ike-proposal"),
            (r"^(?:proposal|set\s+transform-set)\s+(.+)", "ipsec-proposal"),
            (r"^(?:remote-address|set\s+peer|address)\s+(\S+)", "peer"),
        ):
            match = re.match(pattern, stripped, re.IGNORECASE)
            if match:
                value = match.group(1).strip().split()[0]
                refs.add(f"{prefix}:{value}")
    return refs


def _redact_ipsec_sensitive_line(line: str) -> str:
    redacted = re.sub(
        r"(\b(?:pre-shared-key|shared-key|password|secret|key)\b(?:\s+cipher)?\s+)\S+",
        r"\1<redacted>",
        line,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"(\bcrypto\s+(?:isakmp|ikev1|ikev2)\s+key\s+)\S+",
        r"\1<redacted>",
        redacted,
        flags=re.IGNORECASE,
    )
    return redacted


def _extract_firewall_profile_name(text: str) -> str:
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    for pattern in (
        r"^(?:url-filter|antivirus|av-profile|intrusion|ips|application|user-profile)\s+(?:profile\s+)?(\S+)",
        r"^profile\s+(\S+)",
    ):
        match = re.match(pattern, first, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_firewall_profile_tags(text: str) -> set[str]:
    tags = {"firewall", "profile"}
    if re.search(r"\burl-filter\b", text, re.IGNORECASE):
        tags.add("url-filter")
    if re.search(r"\b(?:antivirus|av-profile)\b", text, re.IGNORECASE):
        tags.add("av")
    if re.search(r"\b(?:intrusion|ips)\b", text, re.IGNORECASE):
        tags.add("ips")
    if re.search(r"\bapplication\b", text, re.IGNORECASE):
        tags.add("application")
    if re.search(r"\buser\b", text, re.IGNORECASE):
        tags.add("user")
    return tags


def _extract_time_range_name(first_line: str) -> str:
    match = re.match(r"^time-range\s+(\S+)", first_line.strip(), re.IGNORECASE)
    return match.group(1) if match else ""


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
        match = re.match(r"^(?:time-range|schedule)\s+(\S+)", stripped, re.IGNORECASE)
        if match:
            refs.add(f"time-range:{match.group(1)}")
        match = re.match(r"^(?:profile|url-filter\s+profile|antivirus\s+profile|av-profile|ips\s+profile)\s+(\S+)", stripped, re.IGNORECASE)
        if match:
            refs.add(f"profile:{match.group(1)}")

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
            refs.update(_extract_inline_policy_schedule_refs(stripped))
            refs.update(_extract_inline_policy_profile_refs(stripped))
    return refs


def _extract_inline_policy_schedule_refs(line: str) -> set[str]:
    refs: set[str] = set()
    for pattern in (
        r"\bschedule\s+(\S+)",
        r"\btime-range\s+(\S+)",
    ):
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            refs.add(f"time-range:{match.group(1)}")
    return refs


def _extract_inline_policy_profile_refs(line: str) -> set[str]:
    refs: set[str] = set()
    for pattern in (
        r"\bprofile\s+(\S+)",
        r"\burl-filter\s+profile\s+(\S+)",
        r"\bantivirus\s+profile\s+(\S+)",
        r"\bav-profile\s+(\S+)",
        r"\bips\s+profile\s+(\S+)",
    ):
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            refs.add(f"profile:{match.group(1)}")
    return refs


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result
