from __future__ import annotations

from dataclasses import dataclass, field

from core.domain import DeviceDomain
from core.ir_models import IRConfig
from core.ir_models.enums import ConversionStatus, IRRiskLevel
from core.renderer.base import RenderResult
from core.validator.base import ValidationCategory, ValidationIssue

# Minimum OSPF data fields that must be populated for auto-verification.
# If all are empty, the check is insufficient and must be manual_review.
_OSPF_REQUIRED_FOR_AUTO = ("networks", "areas", "passive_interfaces")


@dataclass
class SemanticValidator:
    src_domain: DeviceDomain
    tgt_domain: DeviceDomain

    def validate(
        self,
        ir: IRConfig,
        render_result: RenderResult | None = None,
    ) -> tuple[list[ValidationIssue], dict]:
        issues: list[ValidationIssue] = []
        metrics = {
            "checked": [],
            "passed_checks": [],
            "failed_checks": [],
            "warning_checks": [],
            "info_checks": [],
        }

        if self.src_domain == DeviceDomain.SWITCH or self.tgt_domain == DeviceDomain.SWITCH:
            self._check_switch(ir, issues, metrics)

        if self.src_domain == DeviceDomain.ROUTER or self.tgt_domain == DeviceDomain.ROUTER:
            self._check_router(ir, issues, metrics)

        if self.src_domain == DeviceDomain.FIREWALL or self.tgt_domain == DeviceDomain.FIREWALL:
            self._check_firewall(ir, issues, metrics)

        return issues, metrics

    # --- helpers ---

    def _record_check(self, check_name: str, issues: list, metrics: dict,
                      field_prefix: str) -> None:
        metrics["checked"].append(check_name)
        check_issues = [i for i in issues
                        if i.field and i.field.startswith(f"semantic:{field_prefix}")]
        if not check_issues:
            metrics["passed_checks"].append(check_name)
            return
        _level = {IRRiskLevel.LOW: 0, IRRiskLevel.MEDIUM: 1,
                  IRRiskLevel.HIGH: 2, IRRiskLevel.CRITICAL: 3}
        max_sev = max(check_issues,
                      key=lambda i: _level.get(i.severity, 0)).severity
        bucket = {
            IRRiskLevel.HIGH: "failed_checks",
            IRRiskLevel.CRITICAL: "failed_checks",
            IRRiskLevel.MEDIUM: "warning_checks",
            IRRiskLevel.LOW: "info_checks",
        }.get(max_sev, "info_checks")
        metrics[bucket].append(check_name)

    # --- SWITCH checks ---

    def _check_switch(
        self, ir: IRConfig, issues: list, metrics: dict,
    ) -> None:
        self._check_vlan_names(ir, issues, metrics)
        self._check_svi_ips(ir, issues, metrics)
        self._check_fhrp(ir, issues, metrics)
        self._check_acl_entries(ir, issues, metrics)
        self._check_acl_bindings(ir, issues, metrics)
        self._check_static_routes(ir, issues, metrics)
        self._check_ospf(ir, issues, metrics)
        self._check_lag_members(ir, issues, metrics)

    def _check_vlan_names(self, ir: IRConfig, issues: list, metrics: dict) -> None:
        for vlan in ir.vlans:
            if vlan.conversion_status != ConversionStatus.EXACT:
                issues.append(self._make_issue(
                    "vlan_name", IRRiskLevel.MEDIUM,
                    f"VLAN {vlan.vid} name status: {vlan.conversion_status.value}"
                    f"{' (' + vlan.reason + ')' if vlan.reason else ''}",
                ))
        self._record_check("vlan_names", issues, metrics, "vlan_name")

    def _check_svi_ips(self, ir: IRConfig, issues: list, metrics: dict) -> None:
        missing = [s for s in ir.svis
                   if not s.ip and s.conversion_status == ConversionStatus.EXACT]
        for svi in missing:
            issues.append(self._make_issue(
                "svi_ip", IRRiskLevel.HIGH,
                f"SVI {svi.vid}: IP address missing after translation",
            ))
        status_issues = [s for s in ir.svis
                         if s.conversion_status != ConversionStatus.EXACT]
        for svi in status_issues:
            issues.append(self._make_issue(
                "svi_ip", IRRiskLevel.MEDIUM,
                f"SVI {svi.vid}: {svi.conversion_status.value}"
                f"{' (' + svi.reason + ')' if svi.reason else ''}",
            ))
        self._record_check("svi_ips", issues, metrics, "svi_ip")

    def _check_fhrp(self, ir: IRConfig, issues: list, metrics: dict) -> None:
        for svi in ir.svis:
            for fhrp in svi.fhrp:
                if fhrp.conversion_status != ConversionStatus.EXACT:
                    issues.append(self._make_issue(
                        "fhrp", IRRiskLevel.MEDIUM,
                        f"VRRP group {fhrp.group_id} on SVI {svi.vid}: "
                        f"{fhrp.conversion_status.value}"
                        f"{' (' + fhrp.reason + ')' if fhrp.reason else ''}",
                    ))
        self._record_check("fhrp", issues, metrics, "fhrp")

    def _check_acl_entries(self, ir: IRConfig, issues: list, metrics: dict) -> None:
        for acl in ir.acls:
            entries = acl.entries
            if not entries:
                continue

            for i in range(len(entries) - 1):
                if (entries[i].sequence is not None and
                        entries[i + 1].sequence is not None and
                        entries[i].sequence >= entries[i + 1].sequence):
                    issues.append(self._make_issue(
                        "acl_order", IRRiskLevel.HIGH,
                        f"ACL {acl.number or acl.name}: sequence order issue "
                        f"at entry {entries[i].sequence} -> {entries[i + 1].sequence}",
                    ))
                    break

            entries_with_none_src = [e for e in entries
                                     if e.action == "permit" and
                                     e.protocol == "ip" and
                                     e.src is None and e.dst is None]
            if entries_with_none_src:
                issues.append(self._make_issue(
                    "acl_wildcard", IRRiskLevel.LOW,
                    f"ACL {acl.number or acl.name}: {len(entries_with_none_src)} "
                    f"entries with 'permit ip any any' semantics",
                ))
        self._record_check("acl_entries", issues, metrics, "acl_")

    def _check_acl_bindings(self, ir: IRConfig, issues: list, metrics: dict) -> None:
        for svi in ir.svis:
            if not svi.acl_in:
                continue
            acl_ids = {str(a.number or a.name) for a in ir.acls}
            if str(svi.acl_in) not in acl_ids:
                issues.append(self._make_issue(
                    "acl_binding", IRRiskLevel.HIGH,
                    f"SVI {svi.vid}: ACL '{svi.acl_in}' referenced but "
                    f"not found in IR acls definition",
                ))
        self._record_check("acl_bindings", issues, metrics, "acl_binding")

    def _check_static_routes(self, ir: IRConfig, issues: list, metrics: dict) -> None:
        for route in ir.static_routes:
            status = route.conversion_status
            if status != ConversionStatus.EXACT:
                issues.append(self._make_issue(
                    "static_route",
                    IRRiskLevel.HIGH if status == ConversionStatus.UNSUPPORTED
                    else IRRiskLevel.MEDIUM,
                    f"Static route {route.prefix}/{route.mask} -> {route.nexthop}: "
                    f"{status.value}{' (' + route.reason + ')' if route.reason else ''}",
                ))
        self._record_check("static_routes", issues, metrics, "static_route")

    def _check_ospf(self, ir: IRConfig, issues: list, metrics: dict) -> None:
        for proc in ir.ospf:
            # 1. Conversion status (existing shallow check)
            if proc.conversion_status != ConversionStatus.EXACT:
                issues.append(self._make_issue(
                    "ospf", IRRiskLevel.HIGH,
                    f"OSPF process {proc.process_id}: {proc.conversion_status.value}"
                    f"{' (' + proc.reason + ')' if proc.reason else ''}",
                    rule_id="ospf:conversion_status",
                    source_ref=f"ir.ospf[{proc.process_id}]",
                ))

            # 2. Info sufficiency: if only process_id exists, flag manual_review
            has_substance = any(
                getattr(proc, f, None)
                for f in _OSPF_REQUIRED_FOR_AUTO
            )
            if not has_substance and proc.conversion_status == ConversionStatus.EXACT:
                issues.append(self._make_issue(
                    "ospf", IRRiskLevel.MEDIUM,
                    f"OSPF process {proc.process_id}: only process_id available, "
                    f"no networks/areas/passive_interfaces — manual review required",
                    category_override=ValidationCategory.MANUAL_REVIEW,
                    rule_id="ospf:insufficient_info",
                    source_ref=f"ir.ospf[{proc.process_id}]",
                ))

            # 3. Network area references: each network must reference a defined area
            if proc.networks and proc.areas:
                area_ids: set[str] = set()
                for a in proc.areas:
                    aid = a.get("area_id") or a.get("id") or ""
                    if aid:
                        area_ids.add(str(aid))
                for net in proc.networks:
                    net_area = str(net.get("area", ""))
                    if net_area and net_area not in area_ids:
                        issues.append(self._make_issue(
                            "ospf", IRRiskLevel.HIGH,
                            f"OSPF process {proc.process_id}: network area "
                            f"'{net_area}' not found in defined areas {area_ids}",
                            rule_id="ospf:network_area_mismatch",
                            source_ref=f"ir.ospf[{proc.process_id}].networks",
                        ))

            # 4. Area type conflicts
            if proc.areas:
                area_types: dict[str, str] = {}
                for a in proc.areas:
                    aid = a.get("area_id") or a.get("id") or ""
                    atype = a.get("type", "normal")
                    if aid and aid in area_types and area_types[aid] != atype:
                        issues.append(self._make_issue(
                            "ospf", IRRiskLevel.MEDIUM,
                            f"OSPF process {proc.process_id}: area '{aid}' has "
                            f"conflicting types ({area_types[aid]} vs {atype})",
                            rule_id="ospf:area_type_conflict",
                            source_ref=f"ir.ospf[{proc.process_id}].areas",
                        ))
                    elif aid:
                        area_types[aid] = atype

        self._record_check("ospf", issues, metrics, "ospf")

    def _check_lag_members(self, ir: IRConfig, issues: list, metrics: dict) -> None:
        for lag in ir.lags:
            if lag.member_ports:
                if lag.conversion_status != ConversionStatus.EXACT:
                    issues.append(self._make_issue(
                        "lag_member", IRRiskLevel.MEDIUM,
                        f"LAG {lag.lag_id}: {lag.conversion_status.value}"
                        f"{' (' + lag.reason + ')' if lag.reason else ''}",
                    ))
        self._record_check("lag_members", issues, metrics, "lag_member")

    # --- ROUTER checks (framework, IR-level only) ---

    def _check_router(self, ir: IRConfig, issues: list, metrics: dict) -> None:
        self._record_check("router_semantic", issues, metrics, "router_")
        has_router_data = bool(ir.static_routes or ir.ospf or ir.bgp
                               or ir.vrfs or ir.pbrs or ir.nat_rules
                               or ir.ipsec_vpns)
        if not has_router_data:
            return

        # OSPF deep check borrowed from _check_switch
        if ir.ospf:
            self._check_ospf(ir, issues, metrics)

        for route in ir.static_routes:
            if route.vrf:
                issues.append(self._make_issue(
                    "router_vrf_route", IRRiskLevel.MEDIUM,
                    f"VRF static route {route.prefix}/{route.mask} "
                    f"in VRF '{route.vrf}': verify VRF context preserved",
                ))
        for bgp in ir.bgp:
            if bgp.conversion_status != ConversionStatus.EXACT:
                issues.append(self._make_issue(
                    "router_bgp", IRRiskLevel.HIGH,
                    f"BGP AS {bgp.asn}: {bgp.conversion_status.value}"
                    f"{' (' + bgp.reason + ')' if bgp.reason else ''}",
                ))
        for vrf in ir.vrfs:
            if vrf.conversion_status != ConversionStatus.EXACT:
                issues.append(self._make_issue(
                    "router_vrf", IRRiskLevel.HIGH,
                    f"VRF {vrf.name}: {vrf.conversion_status.value}"
                    f"{' (' + vrf.reason + ')' if vrf.reason else ''}",
                ))
        for nat in ir.nat_rules:
            issues.append(self._make_issue(
                "router_nat", IRRiskLevel.MEDIUM,
                f"NAT rule '{nat.name or 'unnamed'}': verify NAT semantics preserved",
            ))
        for pbr in ir.pbrs:
            issues.append(self._make_issue(
                "router_pbr", IRRiskLevel.MEDIUM,
                f"PBR '{pbr.name}': verify PBR semantics preserved",
            ))
        for ipsec in ir.ipsec_vpns:
            issues.append(self._make_issue(
                "router_ipsec", IRRiskLevel.MEDIUM,
                f"IPsec VPN '{ipsec.type}': verify IPsec semantics preserved",
            ))

    # --- FIREWALL checks (framework, IR-level only) ---

    def _check_firewall(self, ir: IRConfig, issues: list, metrics: dict) -> None:
        self._record_check("firewall_semantic", issues, metrics, "firewall_")
        has_fw_data = bool(ir.zones or ir.address_objects
                           or ir.service_objects or ir.security_policies
                           or ir.nat_rules)
        if not has_fw_data:
            return

        for z in ir.zones:
            if z.conversion_status != ConversionStatus.EXACT:
                issues.append(self._make_issue(
                    "firewall_zone", IRRiskLevel.HIGH,
                    f"Zone '{z.name}': {z.conversion_status.value}"
                    f"{' (' + z.reason + ')' if z.reason else ''}",
                ))
        for ao in ir.address_objects:
            if ao.conversion_status != ConversionStatus.EXACT:
                issues.append(self._make_issue(
                    "firewall_address_object", IRRiskLevel.HIGH,
                    f"Address '{ao.name}': {ao.conversion_status.value}"
                    f"{' (' + ao.reason + ')' if ao.reason else ''}",
                ))
        for so in ir.service_objects:
            if so.conversion_status != ConversionStatus.EXACT:
                issues.append(self._make_issue(
                    "firewall_service_object", IRRiskLevel.HIGH,
                    f"Service '{so.name}': {so.conversion_status.value}"
                    f"{' (' + so.reason + ')' if so.reason else ''}",
                ))
        for sp in ir.security_policies:
            if sp.conversion_status != ConversionStatus.EXACT:
                issues.append(self._make_issue(
                    "firewall_security_policy", IRRiskLevel.HIGH,
                    f"Policy '{sp.name}': {sp.conversion_status.value}"
                    f"{' (' + sp.reason + ')' if sp.reason else ''}",
                ))

    def _make_issue(
        self, field: str, severity: IRRiskLevel, message: str,
        category_override: ValidationCategory | None = None,
        rule_id: str | None = None,
        source_ref: str | None = None,
    ) -> ValidationIssue:
        return ValidationIssue(
            category=category_override or ValidationCategory.SEMANTIC,
            severity=severity,
            message=message,
            field=f"semantic:{field}",
            rule_id=rule_id,
            source_ref=source_ref,
        )
