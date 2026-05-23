from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from core.ir_models.base import SourceSpan
from core.ir_models.enums import IRRiskLevel
from core.validator.base import ValidationCategory, ValidationIssue

if TYPE_CHECKING:
    from core.vendor.base import VendorPlatformProfile


@dataclass
class BasicSyntaxValidator:
    comment_char: str = "!"
    target_profile: VendorPlatformProfile | None = None

    def validate(self, config_text: str) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        lines = config_text.split("\n")

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(self.comment_char):
                continue

            self._check_ip_address(line, stripped, lineno, issues)
            self._check_subnet_mask(line, stripped, lineno, issues)
            self._check_vlan_range(line, stripped, lineno, issues)
            self._check_interface_name(line, stripped, lineno, issues)

        return issues

    def _check_ip_address(
        self,
        line: str,
        stripped: str,
        lineno: int,
        issues: list[ValidationIssue],
    ) -> None:
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', stripped)
        for ip in ips:
            octets = ip.split(".")
            if any(int(o) > 255 for o in octets):
                issues.append(ValidationIssue(
                    category=ValidationCategory.SYNTAX,
                    severity=IRRiskLevel.HIGH,
                    message=f"Invalid IP address: {ip}",
                    field="ip_address",
                    line=lineno,
                    source_text=line,
                ))

    def _check_subnet_mask(
        self,
        line: str,
        stripped: str,
        lineno: int,
        issues: list[ValidationIssue],
    ) -> None:
        masks = re.findall(r'(?:255\.\d{1,3}\.\d{1,3}\.\d{1,3})', stripped)
        for mask in masks:
            octets = mask.split(".")
            try:
                ints = [int(o) for o in octets]
            except ValueError:
                continue

            valid = all(0 <= o <= 255 for o in ints)
            if not valid:
                issues.append(ValidationIssue(
                    category=ValidationCategory.SYNTAX,
                    severity=IRRiskLevel.HIGH,
                    message=f"Invalid subnet mask: {mask}",
                    field="subnet_mask",
                    line=lineno,
                    source_text=line,
                ))
            else:
                # Check contiguous 1s
                binary = "".join(f"{o:08b}" for o in ints)
                if "01" in binary.rstrip("0"):
                    issues.append(ValidationIssue(
                        category=ValidationCategory.SYNTAX,
                        severity=IRRiskLevel.MEDIUM,
                        message=f"Non-contiguous subnet mask: {mask}",
                        field="subnet_mask",
                        line=lineno,
                        source_text=line,
                    ))

    def _check_vlan_range(
        self,
        line: str,
        stripped: str,
        lineno: int,
        issues: list[ValidationIssue],
    ) -> None:
        vlan_nums = re.findall(r'\bvlan\s+(\d+)\b', stripped, re.IGNORECASE)
        vlan_nums += re.findall(r'\bvlan\s+(\d+)[,\-\s]', stripped, re.IGNORECASE)
        for vlan_str in vlan_nums:
            try:
                vid = int(vlan_str)
                if vid < 1 or vid > 4094:
                    issues.append(ValidationIssue(
                        category=ValidationCategory.SYNTAX,
                        severity=IRRiskLevel.HIGH,
                        message=f"VLAN ID out of range (1-4094): {vid}",
                        field="vlan_id",
                        line=lineno,
                        source_text=line,
                    ))
            except ValueError:
                pass

    def _check_interface_name(
        self,
        line: str,
        stripped: str,
        lineno: int,
        issues: list[ValidationIssue],
    ) -> None:
        iface_match = re.match(
            r'^interface\s+(\S+)',
            stripped,
            re.IGNORECASE,
        )
        if iface_match:
            full_name = iface_match.group(1)
            naming = getattr(self.target_profile, "interface_naming", None) if self.target_profile else None
            if naming:
                patterns = naming.physical_patterns or []
                is_known = any(
                    re.match(p, full_name, re.IGNORECASE)
                    for p in patterns
                ) if patterns else False
                is_special = any(
                    full_name.lower().startswith(prefix.lower())
                    for prefix in [
                        naming.svi_prefix,
                        naming.loopback_prefix,
                        naming.port_channel_prefix,
                        naming.tunnel_prefix,
                        naming.management_prefix,
                    ]
                )
                if not is_known and not is_special:
                    issues.append(ValidationIssue(
                        category=ValidationCategory.SYNTAX,
                        severity=IRRiskLevel.LOW,
                        message=f"Interface '{full_name}' does not match "
                                f"known patterns for {self.target_profile.key}",
                        field="interface_name",
                        line=lineno,
                        source_text=line,
                    ))
