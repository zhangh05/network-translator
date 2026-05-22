from __future__ import annotations

import re

from core.domain import DeviceDomain
from core.parser import register_parser, BaseParser, ParserContext, ParseResult
from core.parser.shared import parse_vlan_range, cidr_to_mask
from core.ir_models import (
    IRConfig,
    IRUnknownBlock,
    IRVlan,
    IRSvi,
    IRInterface,
    IRStaticRoute,
    IRAcl,
    IRAclEntry,
    IRFhrp,
    IRLag,
    IROspf,
    IRStp,
    IRAaa,
    IRManagement,
)
from core.ir_models.enums import IRType, IRInterfaceType, IRFhrpProtocol
from core.ir_models.base import SourceSpan


class H3CComwareParser(BaseParser):
    vendor = "h3c"
    platform = "comware"
    supported_domains = [DeviceDomain.SWITCH, DeviceDomain.ROUTER]

    def parse(self, config_text: str, context: ParserContext | None = None) -> ParseResult:
        meta = self.make_meta(context)
        ir = IRConfig(meta=meta)

        if not config_text or not config_text.strip():
            return ParseResult(
                ir=ir,
                parsed_line_count=0,
                total_line_count=0,
                unknown_lines=[],
            )

        lines = config_text.rstrip("\n").split("\n")
        total = len(lines)
        consumed_lines: set[int] = set()
        lag_members: dict[int, list[str]] = {}

        i = 0
        while i < total:
            raw_line = lines[i]
            stripped = raw_line.strip()

            if not stripped or stripped == "#":
                consumed_lines.add(i + 1)
                i += 1
                continue

            if stripped.startswith("sysname"):
                parts = stripped.split(maxsplit=1)
                if len(parts) > 1:
                    meta.hostname = parts[1]
                consumed_lines.add(i + 1)
                i += 1
            elif stripped.startswith("vlan ") and not stripped.startswith("vlan batch") and "mapping" not in stripped:
                block_lines, end = self._collect_block(lines, i)
                self._parse_vlan_block(block_lines, ir, consumed_lines, i)
                i = end
            elif stripped.startswith("stp region-configuration"):
                block_lines, end = self._collect_block(lines, i)
                self._parse_stp_region(block_lines, ir, consumed_lines, i)
                i = end
            elif stripped.startswith("stp instance") or stripped.startswith("stp global"):
                consumed_lines.add(i + 1)
                i += 1
            elif stripped.startswith("interface "):
                block_lines, end = self._collect_block(lines, i)
                self._parse_interface_block(block_lines, ir, consumed_lines, i, lag_members)
                i = end
            elif stripped.startswith("ospf "):
                block_lines, end = self._collect_block(lines, i)
                self._parse_ospf_block(block_lines, ir, consumed_lines, i)
                i = end
            elif stripped.startswith("ip route-static"):
                self._parse_static_route(stripped, ir, consumed_lines, i)
                i += 1
            elif stripped.startswith("acl number"):
                block_lines, end = self._collect_block(lines, i)
                self._parse_acl_block(block_lines, ir, consumed_lines, i)
                i = end
            elif stripped.startswith("lldp"):
                self._add_to_management(ir, "lldp", stripped)
                consumed_lines.add(i + 1)
                i += 1
            elif stripped.startswith("snmp-agent"):
                self._add_to_management(ir, "snmp", stripped)
                consumed_lines.add(i + 1)
                i += 1
            elif stripped.startswith("ntp-service"):
                self._add_to_management(ir, "ntp", stripped)
                consumed_lines.add(i + 1)
                i += 1
            elif stripped.startswith("ssh server"):
                self._add_to_management(ir, "ssh", {"server_enable": True})
                consumed_lines.add(i + 1)
                i += 1
            elif stripped.startswith("info-center"):
                self._add_to_management(ir, "syslog", stripped)
                consumed_lines.add(i + 1)
                i += 1
            elif stripped.startswith("hwtacacs scheme"):
                block_lines, end = self._collect_block(lines, i)
                self._parse_hwtacacs(block_lines, ir, consumed_lines, i)
                i = end
            elif stripped.startswith("domain "):
                block_lines, end = self._collect_block(lines, i)
                self._parse_domain_block(block_lines, ir, consumed_lines, i)
                i = end
            elif stripped.startswith("line ") or stripped.startswith("user-group system") or stripped.startswith("local-user"):
                block_lines, end = self._collect_block(lines, i)
                self._parse_aaa_block(block_lines, ir, consumed_lines, i)
                i = end
            elif stripped.startswith("role name"):
                block_lines, end = self._collect_block(lines, i)
                for li in range(1, len(block_lines) + 1):
                    consumed_lines.add(i + li)
                i = end
            elif stripped.startswith("clock timezone") or stripped.startswith("undo ") or stripped.startswith("return"):
                consumed_lines.add(i + 1)
                i += 1
            else:
                known_singles = [
                    "forward-path-detection enable", "irf mode normal",
                    "ip unreachables enable", "ip ttl-expires enable",
                    "dldp global enable", "burst-mode enable",
                    "system-working-mode standard", "scheduler logfile",
                    "ftp-server", "arp ", "security-enhanced level",
                    "undo ssl", "undo info-center",
                ]
                if any(stripped.startswith(k) for k in known_singles):
                    consumed_lines.add(i + 1)
                    i += 1
                else:
                    block_lines, end = self._collect_block(lines, i)
                    i = end

        unknown_lines = sorted(set(range(1, total + 1)) - consumed_lines)
        if unknown_lines:
            ir.unknown_blocks = self._build_unknown_blocks(lines, unknown_lines)

        for lag in ir.lags:
            if lag.lag_id in lag_members:
                lag.member_ports = lag_members[lag.lag_id]

        parsed_count = len(consumed_lines)

        return ParseResult(
            ir=ir,
            parsed_line_count=parsed_count,
            total_line_count=total,
            unknown_lines=unknown_lines,
        )

    def _collect_block(self, lines: list[str], start: int) -> tuple[list[str], int]:
        block: list[str] = []
        i = start
        while i < len(lines):
            raw = lines[i]
            stripped = raw.strip()
            if not stripped or stripped == "#":
                break
            if i > start and not raw.startswith(" ") and not raw.startswith("\t"):
                break
            block.append(stripped)
            i += 1
        return block, i

    def _parse_vlan_block(self, block_lines: list[str], ir: IRConfig, consumed: set[int], start_line: int):
        first = block_lines[0]
        vid = int(first.split()[1])
        name = None
        for line in block_lines[1:]:
            if line.startswith("name "):
                name = line.split(maxsplit=1)[1]
        span = SourceSpan(start_line=start_line + 1, end_line=start_line + len(block_lines))
        ir.vlans.append(IRVlan(type=IRType.VLAN, source_span=span, vid=vid, name=name))
        for li in range(1, len(block_lines) + 1):
            consumed.add(start_line + li)

    def _parse_stp_region(self, block_lines: list[str], ir: IRConfig, consumed: set[int], start_line: int):
        region = None
        revision = None
        instances: list[dict] = []
        for line in block_lines:
            if line.startswith("region-name "):
                region = line.split(maxsplit=1)[1]
            elif line.startswith("instance "):
                parts = line.split()
                if len(parts) >= 4 and parts[2] == "vlan":
                    inst_id = int(parts[1])
                    vlan_text = " ".join(parts[3:])
                    vlans = parse_vlan_range(vlan_text.replace("to", "-"))
                    instances.append({"id": inst_id, "vlans": vlans})
            elif line.startswith("revision-level "):
                try:
                    revision = int(line.split()[-1])
                except (ValueError, IndexError):
                    pass
        span = SourceSpan(start_line=start_line + 1, end_line=start_line + len(block_lines))
        ir.stp = IRStp(type=IRType.STP, source_span=span, mode="mstp", region=region, revision=revision, instances=instances)
        for li in range(1, len(block_lines) + 1):
            consumed.add(start_line + li)

    def _parse_interface_block(self, block_lines: list[str], ir: IRConfig, consumed: set[int], start_line: int, lag_members: dict[int, list[str]]):
        first = block_lines[0]
        name = first.split(maxsplit=1)[1]
        name_lower = name.lower()

        if name_lower.startswith("bridge-aggregation"):
            m = re.search(r"(\d+)$", name)
            if not m:
                return
            lag_id = int(m.group(1))
            mode = "static"
            for line in block_lines[1:]:
                if "link-aggregation mode dynamic" in line:
                    mode = "lacp"
            span = SourceSpan(start_line=start_line + 1, end_line=start_line + len(block_lines))
            ir.lags.append(IRLag(type=IRType.LAG, source_span=span, lag_id=lag_id, member_ports=[], mode=mode))
            for li in range(1, len(block_lines) + 1):
                consumed.add(start_line + li)

        elif name_lower.startswith("vlan-interface"):
            m = re.search(r"(\d+)$", name)
            if not m:
                return
            vid = int(m.group(1))
            description = None
            ip = None
            mask = None
            fhrp_list: list = []
            acl_in = None
            acl_out = None
            for line in block_lines[1:]:
                if line.startswith("description "):
                    description = line.split(maxsplit=1)[1]
                elif line.startswith("ip address "):
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[2]
                        mask = parts[3] if len(parts) > 3 else None
                elif line.startswith("vrrp vrid "):
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    vrid = int(parts[2])
                    if "virtual-ip" in line and len(parts) >= 5:
                        vip = parts[4]
                        fhrp_list.append(IRFhrp(
                            type=IRType.FHRP, source_span=SourceSpan(start_line=start_line + 1, end_line=start_line + len(block_lines)),
                            protocol=IRFhrpProtocol.VRRP, group_id=vrid, virtual_ip=vip,
                        ))
                    elif "priority" in line and len(parts) >= 5:
                        priority = int(parts[4])
                        for f in fhrp_list:
                            if f.group_id == vrid:
                                f.priority = priority
                elif line.startswith("packet-filter "):
                    parts = line.split()
                    if len(parts) >= 2:
                        acl_num = parts[1]
                        direction = "inbound" if "inbound" in line else "outbound"
                        if direction == "inbound":
                            acl_in = acl_num
                        else:
                            acl_out = acl_num
            span = SourceSpan(start_line=start_line + 1, end_line=start_line + len(block_lines))
            ir.svis.append(IRSvi(
                type=IRType.SVI, source_span=span, vid=vid,
                ip=ip, mask=mask, fhrp=fhrp_list,
                acl_in=acl_in, acl_out=acl_out,
                description=description,
            ))
            for li in range(1, len(block_lines) + 1):
                consumed.add(start_line + li)

        elif name_lower.startswith("loopback"):
            description = None
            ip = None
            mask = None
            for line in block_lines[1:]:
                if line.startswith("description "):
                    description = line.split(maxsplit=1)[1]
                elif line.startswith("ip address "):
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[2]
                        mask = parts[3] if len(parts) > 3 else None
            span = SourceSpan(start_line=start_line + 1, end_line=start_line + len(block_lines))
            ir.interfaces.append(IRInterface(
                type=IRType.INTERFACE, source_span=span,
                iftype=IRInterfaceType.LOOPBACK, name=name,
                description=description, ip=ip, mask=mask,
            ))
            for li in range(1, len(block_lines) + 1):
                consumed.add(start_line + li)

        elif name_lower.startswith("null"):
            span = SourceSpan(start_line=start_line + 1, end_line=start_line + len(block_lines))
            ir.interfaces.append(IRInterface(
                type=IRType.INTERFACE, source_span=span,
                iftype=IRInterfaceType.NULL, name=name,
            ))
            for li in range(1, len(block_lines) + 1):
                consumed.add(start_line + li)

        else:
            description = None
            trunk_allowed = None
            trunk_allowed_all = False
            untagged_vlan = None
            lag_group = None
            shutdown = False
            for line in block_lines[1:]:
                if line.startswith("description "):
                    description = line.split(maxsplit=1)[1]
                elif line.startswith("port trunk permit vlan all"):
                    trunk_allowed_all = True
                elif line.startswith("port trunk permit vlan "):
                    vlan_text = line.split("vlan", 1)[1].strip()
                    trunk_allowed = parse_vlan_range(vlan_text)
                elif line.startswith("port access vlan "):
                    try:
                        untagged_vlan = int(line.split()[-1])
                    except (ValueError, IndexError):
                        pass
                elif line.startswith("port link-aggregation group "):
                    try:
                        lag_group = int(line.split()[-1])
                    except (ValueError, IndexError):
                        pass
            span = SourceSpan(start_line=start_line + 1, end_line=start_line + len(block_lines))
            ir.interfaces.append(IRInterface(
                type=IRType.INTERFACE, source_span=span,
                iftype=IRInterfaceType.PHYSICAL, name=name,
                description=description,
                trunk_allowed=trunk_allowed, trunk_allowed_all=trunk_allowed_all,
                untagged_vlan=untagged_vlan,
                lag_group=lag_group, shutdown=shutdown,
            ))
            if lag_group is not None:
                if lag_group not in lag_members:
                    lag_members[lag_group] = []
                lag_members[lag_group].append(name)
            for li in range(1, len(block_lines) + 1):
                consumed.add(start_line + li)

    def _parse_ospf_block(self, block_lines: list[str], ir: IRConfig, consumed: set[int], start_line: int):
        first = block_lines[0]
        m = re.match(r"ospf (\d+) router-id (\S+)", first)
        if not m:
            return
        process_id = int(m.group(1))
        router_id = m.group(2)
        silent_all = False
        undo_silent = []
        networks = []
        areas = []
        current_area = None
        import_route_static = False

        for line in block_lines:
            if line.startswith("import-route static"):
                import_route_static = True
            elif line.startswith("silent-interface all"):
                silent_all = True
            elif line.startswith("undo silent-interface "):
                iface = line[len("undo silent-interface "):].strip()
                if iface:
                    undo_silent.append(iface)
            elif line.startswith("area "):
                area_id = line.split(maxsplit=1)[1]
                current_area = area_id
                areas.append({"area_id": area_id, "type": "normal"})
            elif line.startswith("network "):
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[1]
                    wildcard = parts[2]
                    networks.append({"ip": ip, "wildcard": wildcard, "area": current_area})

        span = SourceSpan(start_line=start_line + 1, end_line=start_line + len(block_lines))

        notes = None
        if undo_silent:
            notes = f"undo silent-interface: {', '.join(undo_silent)}"

        ir.ospf.append(IROspf(
            type=IRType.OSPF, source_span=span,
            process_id=process_id, router_id=router_id,
            networks=networks, areas=areas,
            redistributes=[], review_notes=notes,
            passive_interfaces=[],
        ))
        for li in range(1, len(block_lines) + 1):
            consumed.add(start_line + li)

    def _parse_static_route(self, line: str, ir: IRConfig, consumed: set[int], line_no: int):
        parts = line.split()
        if len(parts) < 4:
            return
        prefix = parts[2]
        mask_or_cidr = parts[3]
        if mask_or_cidr.isdigit():
            mask = cidr_to_mask(int(mask_or_cidr))
        else:
            mask = mask_or_cidr
        nexthop = parts[4] if len(parts) > 4 else ""
        span = SourceSpan(start_line=line_no + 1, end_line=line_no + 1)
        ir.static_routes.append(IRStaticRoute(
            type=IRType.STATIC_ROUTE, source_span=span,
            prefix=prefix, mask=mask, nexthop=nexthop,
        ))
        consumed.add(line_no + 1)

    def _parse_acl_block(self, block_lines: list[str], ir: IRConfig, consumed: set[int], start_line: int):
        first = block_lines[0]
        m = re.match(r"acl number (\d+)", first)
        if not m:
            return
        acl_id = int(m.group(1))
        if acl_id >= 3000:
            acl_type = "advanced"
        elif acl_id >= 2000:
            acl_type = "basic"
        elif acl_id >= 100:
            acl_type = "extended"
        else:
            acl_type = "standard"
        name = None
        entries = []
        for line in block_lines[1:]:
            if line.startswith("rule "):
                entry = self._parse_acl_rule(line)
                if entry:
                    entries.append(entry)
        span = SourceSpan(start_line=start_line + 1, end_line=start_line + len(block_lines))
        ir.acls.append(IRAcl(
            type=IRType.ACL, source_span=span,
            acl_type=acl_type, number=acl_id, name=name,
            entries=entries,
        ))
        for li in range(1, len(block_lines) + 1):
            consumed.add(start_line + li)

    def _parse_acl_rule(self, line: str) -> IRAclEntry | None:
        m = re.match(r"rule\s+(\d+)\s+(permit|deny)\s+(.*)", line)
        if not m:
            return None
        seq = int(m.group(1))
        action = m.group(2)
        rest = m.group(3).strip()
        src = None
        src_wc = None
        dst = None
        dst_wc = None
        protocol = None
        if rest.startswith("ip"):
            protocol = "ip"
            after_proto = rest[2:].strip()
            if after_proto.startswith("source "):
                parts = after_proto.split()
                if len(parts) >= 3:
                    src = parts[1]
                    src_wc = parts[2]
                    rest_after = " ".join(parts[3:])
                    if "destination" in rest_after:
                        dm = re.search(r"destination\s+(\S+)\s+(\S+)", rest_after)
                        if dm:
                            dst = dm.group(1)
                            dst_wc = dm.group(2)
        elif rest.startswith("source "):
            parts = rest.split()
            if len(parts) >= 3:
                src = parts[1]
                src_wc = parts[2]
                rest_after = " ".join(parts[3:])
                if "destination" in rest_after:
                    dm = re.search(r"destination\s+(\S+)\s+(\S+)", rest_after)
                    if dm:
                        dst = dm.group(1)
                        dst_wc = dm.group(2)
        return IRAclEntry(action=action, sequence=seq, protocol=protocol,
                          src=src, src_wildcard=src_wc,
                          dst=dst, dst_wildcard=dst_wc)

    def _add_to_management(self, ir: IRConfig, category: str, value):
        if ir.management is None:
            span = SourceSpan(start_line=1, end_line=1)
            ir.management = IRManagement(type=IRType.MANAGEMENT, source_span=span)
        if category == "lldp":
            if ir.management.dns is None:
                ir.management.dns = {}
            ir.management.dns["lldp"] = str(value)
        elif category == "snmp":
            ir.management.snmp.append({"raw": str(value)})
        elif category == "ntp":
            ir.management.ntp.append({"raw": str(value)})
        elif category == "syslog":
            ir.management.syslog.append({"raw": str(value)})
        elif category == "ssh":
            if ir.management.ssh is None:
                ir.management.ssh = {}
            if isinstance(value, dict):
                ir.management.ssh.update(value)
            else:
                ir.management.ssh["raw"] = str(value)

    def _parse_hwtacacs(self, block_lines: list[str], ir: IRConfig, consumed: set[int], start_line: int):
        if ir.aaa is None:
            span = SourceSpan(start_line=start_line + 1, end_line=start_line + len(block_lines))
            ir.aaa = IRAaa(type=IRType.AAA, source_span=span)
        ir.aaa.servers.append({"type": "hwtacacs", "raw": "\n".join(block_lines)})
        for li in range(1, len(block_lines) + 1):
            consumed.add(start_line + li)

    def _parse_domain_block(self, block_lines: list[str], ir: IRConfig, consumed: set[int], start_line: int):
        if ir.aaa is None:
            span = SourceSpan(start_line=start_line + 1, end_line=start_line + len(block_lines))
            ir.aaa = IRAaa(type=IRType.AAA, source_span=span)
        ir.aaa.servers.append({"type": "domain", "raw": "\n".join(block_lines)})
        for li in range(1, len(block_lines) + 1):
            consumed.add(start_line + li)

    def _parse_aaa_block(self, block_lines: list[str], ir: IRConfig, consumed: set[int], start_line: int):
        if ir.aaa is None:
            span = SourceSpan(start_line=start_line + 1, end_line=start_line + len(block_lines))
            ir.aaa = IRAaa(type=IRType.AAA, source_span=span)
        ir.aaa.servers.append({"type": "line_or_user", "raw": "\n".join(block_lines)})
        for li in range(1, len(block_lines) + 1):
            consumed.add(start_line + li)

    def _build_unknown_blocks(self, lines: list[str], unknown_lines: list[int]) -> list[IRUnknownBlock]:
        if not unknown_lines:
            return []
        blocks: list[IRUnknownBlock] = []
        start = unknown_lines[0]
        end = unknown_lines[0]
        for ln in unknown_lines[1:]:
            if ln == end + 1:
                end = ln
            else:
                raw = "\n".join(lines[start - 1:end])
                span = SourceSpan(start_line=start, end_line=end)
                blocks.append(IRUnknownBlock(type=IRType.UNKNOWN, source_span=span, raw_text=raw))
                start = ln
                end = ln
        raw = "\n".join(lines[start - 1:end])
        span = SourceSpan(start_line=start, end_line=end)
        blocks.append(IRUnknownBlock(type=IRType.UNKNOWN, source_span=span, raw_text=raw))
        return blocks


for _domain in [DeviceDomain.SWITCH, DeviceDomain.ROUTER]:
    register_parser(_domain, "comware", H3CComwareParser)
