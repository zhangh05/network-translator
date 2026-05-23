from __future__ import annotations

from dataclasses import dataclass, field

from core.domain import DeviceDomain, FeatureKey
from core.ir_models.enums import IRRiskLevel
from core.vendor.base import VendorPlatformProfile
from core.vendor.enums import FeatureSupportStatus
from core.validator.base import ValidationCategory, ValidationIssue


@dataclass
class CapabilityGapValidator:
    source_profile: VendorPlatformProfile
    target_profile: VendorPlatformProfile
    source_domain: DeviceDomain
    target_domain: DeviceDomain

    def validate(self) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []

        src_caps = self.source_profile.capabilities.get(self.source_domain, {})
        tgt_caps = self.target_profile.capabilities.get(self.target_domain, {})

        all_keys: set[FeatureKey] = set(src_caps.keys()) | set(tgt_caps.keys())

        for key in sorted(all_keys, key=lambda k: k.value):
            src_support = src_caps.get(key)
            tgt_support = tgt_caps.get(key)

            if src_support is None:
                continue

            # Only flag if source has this feature
            if src_support.status == FeatureSupportStatus.UNSUPPORTED:
                continue

            if tgt_support is None:
                issues.append(self._make_issue(
                    key, "unsupported",
                    f"Feature '{key.value}' not defined in target capabilities",
                    IRRiskLevel.HIGH,
                ))
                continue

            if tgt_support.status == FeatureSupportStatus.UNSUPPORTED:
                issues.append(self._make_issue(
                    key, "unsupported",
                    f"Feature '{key.value}' is unsupported on target platform",
                    IRRiskLevel.CRITICAL,
                    tgt_support.notes,
                ))
            elif tgt_support.status == FeatureSupportStatus.PARTIAL:
                issues.append(self._make_issue(
                    key, "partial",
                    f"Feature '{key.value}' has only partial support on target platform",
                    IRRiskLevel.MEDIUM,
                    tgt_support.notes,
                ))

        return issues

    def _make_issue(
        self,
        key: FeatureKey,
        subcategory: str,
        message: str,
        severity: IRRiskLevel,
        notes: str | None = None,
    ) -> ValidationIssue:
        return ValidationIssue(
            category=ValidationCategory.CAPABILITY_GAP,
            severity=severity,
            message=message,
            field=f"capability:{key.value}:{subcategory}",
            suggestion=notes,
        )
