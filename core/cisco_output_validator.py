# -*- coding: utf-8 -*-
"""Cisco output validator: checks for H3C residue and semantic coverage."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from core.h3c_to_cisco import H3C_FORBIDDEN_IN_CISCO, detect_h3c_residue


@dataclass
class ValidationIssue:
    message: str
    severity: str  # "error" | "warning" | "info"
    category: str  # "residue" | "count_mismatch" | "missing_migration" | "manual_review"
    source_count: Optional[int] = None
    target_count: Optional[int] = None


@dataclass
class CiscoValidationReport:
    deployable: bool = True
    manual_review_required: bool = False
    issues: List[ValidationIssue] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)

    def add_issue(self, message: str, severity: str = "warning",
                  category: str = "residue",
                  source_count: Optional[int] = None,
                  target_count: Optional[int] = None):
        self.issues.append(ValidationIssue(
            message=message, severity=severity, category=category,
            source_count=source_count, target_count=target_count,
        ))
        if severity == "error":
            self.deployable = False
            self.manual_review_required = True
        elif severity == "warning":
            self.manual_review_required = True


class CiscoOutputValidator:
    """Validates Cisco IOS translation output for H3C→Cisco translations."""

    def validate(self, source_config: str, translated_config: str) -> CiscoValidationReport:
        report = CiscoValidationReport()
        if not translated_config or not translated_config.strip():
            report.add_issue("翻译结果为空", "error", "missing_migration")
            return report

        # Strip markdown fences if present
        config_content = translated_config
        m = re.search(r"```(?:cisco)?\n(.+?)\n```", translated_config, re.DOTALL)
        if m:
            config_content = m.group(1)

        # 1. Forbidden H3C token detection (fatal if any found)
        residues = detect_h3c_residue(config_content)
        seen_tokens = set()
        for r in residues:
            token = r["token"]
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            report.add_issue(
                f"H3C 语法残留: {token} (上下文: {r['context'][:60]})",
                "error", "residue",
            )

        # 2. SVI count check
        src_svis = re.findall(r"interface\s+Vlan-interface(\d+)", source_config, re.IGNORECASE)
        tgt_svis = re.findall(r"interface\s+Vlan(\d+)", config_content, re.IGNORECASE)
        tgt_vlan_nums = set(tgt_svis)
        src_vlan_nums = set(src_svis)
        if tgt_vlan_nums != src_vlan_nums:
            missing_svis = src_vlan_nums - tgt_vlan_nums
            extra_svis = tgt_vlan_nums - src_vlan_nums
            if missing_svis:
                report.add_issue(
                    f"SVI 遗漏: {len(missing_svis)} 个 SVI 未翻译 "
                    f"(源 {sorted(missing_svis, key=int)})",
                    "error", "count_mismatch",
                    source_count=len(src_svis), target_count=len(tgt_svis),
                )
            if extra_svis:
                report.add_issue(
                    f"SVI 多余: {len(extra_svis)} 个额外 SVI 出现在输出中",
                    "warning", "count_mismatch",
                    source_count=len(src_svis), target_count=len(tgt_svis),
                )

        # 3. VLAN count check
        src_vlans = set()
        for m in re.finditer(r"^vlan\s+(\d+)", source_config, re.IGNORECASE | re.MULTILINE):
            src_vlans.add(int(m.group(1)))
        tgt_vlans = set()
        for m in re.finditer(r"^vlan\s+(\d+)", config_content, re.IGNORECASE | re.MULTILINE):
            tgt_vlans.add(int(m.group(1)))
        if src_vlans != tgt_vlans:
            missing_v = src_vlans - tgt_vlans
            extra_v = tgt_vlans - src_vlans
            if missing_v:
                report.add_issue(
                    f"VLAN 遗漏: {len(missing_v)} 个 VLAN 未翻译 ({sorted(missing_v)})",
                    "error", "count_mismatch",
                    source_count=len(src_vlans), target_count=len(tgt_vlans),
                )

        # 4. Static route count check
        src_routes = set()
        for m in re.finditer(r"ip\s+route-static\s+(\S+)\s+(\S+)\s+(\S+)",
                             source_config, re.IGNORECASE):
            src_routes.add((m.group(1), m.group(2), m.group(3)))
        tgt_routes = set()
        for m in re.finditer(r"ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)",
                             config_content, re.IGNORECASE):
            tgt_routes.add((m.group(1), m.group(2), m.group(3)))
        if len(src_routes) != len(tgt_routes):
            report.add_issue(
                f"静态路由数量不匹配: 源 {len(src_routes)} 条, 目标 {len(tgt_routes)} 条",
                "error", "count_mismatch",
                source_count=len(src_routes), target_count=len(tgt_routes),
            )

        # 5. ACL entry count check
        src_entries = len(re.findall(r"^\s*rule\s+\d+", source_config, re.IGNORECASE | re.MULTILINE))
        src_acl_blocks = len(re.findall(r"^\s*acl\s+number\s+(\d+)", source_config, re.IGNORECASE | re.MULTILINE))
        tgt_entries = 0
        for m in re.finditer(r"^\s*(?:\d+\s+)?(?:permit|deny)\s+",
                             config_content, re.IGNORECASE | re.MULTILINE):
            tgt_entries += 1
        tgt_acl_blocks = len(re.findall(r"^ip\s+access-list\s+(?:extended|standard)\s+(\d+)",
                                        config_content, re.IGNORECASE | re.MULTILINE))
        if src_acl_blocks != tgt_acl_blocks:
            report.add_issue(
                f"ACL 块数量不匹配: 源 {src_acl_blocks} 个, 目标 {tgt_acl_blocks} 个",
                "error", "count_mismatch",
                source_count=src_acl_blocks, target_count=tgt_acl_blocks,
            )
        else:
            src_non_rule = src_entries
            tgt_non_header = tgt_entries - tgt_acl_blocks
            diff = abs(src_non_rule - tgt_non_header)
            if diff > 2:
                report.add_issue(
                    f"ACL 条目数量差异较大: 源 {src_non_rule} 条, 目标 {tgt_non_header} 条",
                    "warning", "count_mismatch",
                    source_count=src_non_rule, target_count=tgt_non_header,
                )

        # 6. packet-filter → ip access-group migration check
        src_pf = re.findall(r"packet-filter\s+(\d+)\s+inbound", source_config, re.IGNORECASE)
        tgt_ag = re.findall(r"ip\s+access-group\s+(\d+)\s+in", config_content, re.IGNORECASE)
        src_pf_set = set(src_pf)
        tgt_ag_set = set(tgt_ag)
        if src_pf_set != tgt_ag_set:
            missing_migration = src_pf_set - tgt_ag_set
            if missing_migration:
                report.add_issue(
                    f"packet-filter 未迁移为 ip access-group: {missing_migration}",
                    "error", "missing_migration",
                    source_count=len(src_pf_set), target_count=len(tgt_ag_set),
                )
            extra_migrate = tgt_ag_set - src_pf_set
            if extra_migrate:
                report.add_issue(
                    f"额外 ip access-group 绑定: {extra_migrate}",
                    "warning", "missing_migration",
                )

        # 7. Port-channel migration check
        src_lag = re.findall(r"port\s+link-aggregation\s+group\s+(\d+)",
                             source_config, re.IGNORECASE)
        src_lag_set = set(src_lag)
        tgt_cg = re.findall(r"channel-group\s+(\d+)", config_content, re.IGNORECASE)
        tgt_cg_set = set(tgt_cg)
        if src_lag_set != tgt_cg_set:
            missing = src_lag_set - tgt_cg_set
            if missing:
                report.add_issue(
                    f"port link-aggregation group 未迁移为 channel-group: {missing}",
                    "error", "missing_migration",
                    source_count=len(src_lag_set), target_count=len(tgt_cg_set),
                )

        # 8. Bridge-Aggregation → Port-channel check
        src_ba = re.findall(r"interface\s+Bridge-Aggregation(\d+)",
                            source_config, re.IGNORECASE)
        tgt_pc = re.findall(r"interface\s+Port-channel(\d+)",
                            config_content, re.IGNORECASE)
        if len(src_ba) != len(tgt_pc):
            report.add_issue(
                f"Bridge-Aggregation 未完全迁移为 Port-channel: "
                f"源 {len(src_ba)} 个, 目标 {len(tgt_pc)} 个",
                "error", "missing_migration",
                source_count=len(src_ba), target_count=len(tgt_pc),
            )

        # 9. OSPF network count check
        src_networks = re.findall(r"^network\s+\S+\s+\S+", source_config, re.IGNORECASE | re.MULTILINE)
        tgt_networks = set()
        for m in re.finditer(r"network\s+(\S+)\s+(\S+)\s+area\s+(\S+)",
                             config_content, re.IGNORECASE):
            tgt_networks.add((m.group(1), m.group(2)))
        if len(src_networks) != len(tgt_networks):
            report.add_issue(
                f"OSPF network 数量不匹配: 源 {len(src_networks)} 条, 目标 {len(tgt_networks)} 条",
                "warning", "count_mismatch",
                source_count=len(src_networks), target_count=len(tgt_networks),
            )

        # 10. undo silent-interface → no passive-interface count check
        src_undo_silent = re.findall(r"undo\s+silent-interface\s+",
                                     source_config, re.IGNORECASE)
        tgt_no_passive = re.findall(r"no\s+passive-interface\s+",
                                    config_content, re.IGNORECASE)
        if src_undo_silent and not tgt_no_passive:
            report.add_issue(
                f"und silent-interface {len(src_undo_silent)} 条, "
                f"但目标无语",
                "warning", "missing_migration",
                source_count=len(src_undo_silent), target_count=len(tgt_no_passive),
            )
        elif src_undo_silent and len(src_undo_silent) != len(tgt_no_passive):
            report.add_issue(
                f"no passive-interface 数量: 源 undo silent-interface "
                f"{len(src_undo_silent)} 条, 目标 {len(tgt_no_passive)} 条",
                "warning", "count_mismatch",
                source_count=len(src_undo_silent), target_count=len(tgt_no_passive),
            )

        # 11. import-route → redistribute check
        if re.search(r"import-route\s+", source_config, re.IGNORECASE):
            if not re.search(r"redistribute\s+", config_content, re.IGNORECASE):
                report.add_issue(
                    "import-route 未迁移为 redistribute",
                    "warning", "missing_migration",
                )

        # 12. port link-mode bridge removal check
        if re.search(r"port\s+link-mode\s+bridge", source_config, re.IGNORECASE):
            if re.search(r"port\s+link-mode\s+bridge", config_content, re.IGNORECASE):
                report.add_issue(
                    "port link-mode bridge 残留 (应完全移除)",
                    "error", "residue",
                )

        # 13. Vlan-interface → Vlan check (must not have Vlan-interface in output)
        if re.search(r"Vlan-interface", config_content):
            report.add_issue(
                "Vlan-interface 残留在输出中 (应为 Vlan<N>)",
                "error", "residue",
            )

        # 14. Build summary
        errors = [i for i in report.issues if i.severity == "error"]
        warnings = [i for i in report.issues if i.severity == "warning"]
        report.summary = {
            "total_issues": len(report.issues),
            "errors": len(errors),
            "warnings": len(warnings),
            "residue_count": len([i for i in report.issues if i.category == "residue"]),
            "count_mismatch_count": len([i for i in report.issues if i.category == "count_mismatch"]),
            "deployable": report.deployable,
            "manual_review_required": report.manual_review_required,
        }

        return report


def validate_cisco_output(source_config: str, translated_config: str) -> CiscoValidationReport:
    return CiscoOutputValidator().validate(source_config, translated_config)
