from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.ir_models import IRConfig
from core.ir_models.enums import ConversionStatus, IRRiskLevel, IRType
from core.validator.base import ValidationCategory, ValidationIssue


_SEVERITY_MAP = {
    ConversionStatus.UNSUPPORTED: IRRiskLevel.CRITICAL,
    ConversionStatus.NEEDS_REVIEW: IRRiskLevel.MEDIUM,
    ConversionStatus.APPROXIMATED: IRRiskLevel.MEDIUM,
}


_IR_COLLECTION_FIELDS = [
    ("vlans", "vlan"),
    ("svis", "svi"),
    ("interfaces", "interface"),
    ("lags", "lag"),
    ("static_routes", "static_route"),
    ("ospf", "ospf"),
    ("bgp", "bgp"),
    ("acls", "acl"),
    ("zones", "zone"),
    ("address_objects", "address_object"),
    ("service_objects", "service_object"),
    ("security_policies", "security_policy"),
    ("nat_rules", "nat_rule"),
    ("vrfs", "vrf"),
    ("pbrs", "pbr"),
    ("ipsec_vpns", "ipsec_vpn"),
    ("unsupported", "unsupported"),
    ("unknown_blocks", "unknown"),
]


@dataclass
class ConversionValidator:

    def validate(self, ir: IRConfig) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []

        for collection_field, obj_type in _IR_COLLECTION_FIELDS:
            items = getattr(ir, collection_field, [])
            if isinstance(items, list):
                for item in items:
                    self._check_object(item, obj_type, issues)
            else:
                self._check_object(items, obj_type, issues)

        # Check singleton objects: stp, aaa, management
        for singleton_field, obj_type in [
            ("stp", "stp"),
            ("aaa", "aaa"),
            ("management", "management"),
        ]:
            obj = getattr(ir, singleton_field, None)
            if obj is not None:
                self._check_object(obj, obj_type, issues)

        return issues

    def _check_object(
        self,
        obj: Any,
        obj_type: str,
        issues: list[ValidationIssue],
    ) -> None:
        status = getattr(obj, "conversion_status", None)
        if status is not None and status != ConversionStatus.EXACT:
            severity = _SEVERITY_MAP.get(status, IRRiskLevel.LOW)
            source_span = getattr(obj, "source_span", None)
            reason = getattr(obj, "reason", None)
            review_notes = getattr(obj, "review_notes", None)

            message_parts = [f"{obj_type}: {status.value}"]
            if reason:
                message_parts.append(f"({reason})")

            issues.append(ValidationIssue(
                category=ValidationCategory.CONVERSION,
                severity=severity,
                message=" ".join(message_parts),
                field=obj_type,
                source_span=source_span,
                suggestion=review_notes or None,
            ))

        # Check sub-objects (e.g., SVI.fhrp entries) regardless of parent status
        for attr_name in ("entries", "fhrp", "members", "instances"):
            children = getattr(obj, attr_name, None)
            if not children:
                continue
            if isinstance(children, list):
                for child in children:
                    self._check_object(child, f"{obj_type}.{attr_name}", issues)
