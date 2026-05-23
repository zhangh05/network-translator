from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.ir_models.base import SourceSpan
from core.ir_models.enums import IRRiskLevel
from core.vendor.base import VendorPlatformProfile
from core.validator.base import ValidationCategory, ValidationIssue


@dataclass
class ResidueValidator:
    profile: VendorPlatformProfile
    comment_char: str | None = None

    def __post_init__(self):
        if self.comment_char is None:
            self.comment_char = self.profile.comment_char

    def validate(self, config_text: str) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        lines = config_text.split("\n")

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            is_comment = self._is_comment_line(stripped)

            for fp in self.profile.forbidden_patterns:
                try:
                    m = re.search(fp.pattern, stripped)
                except re.error:
                    continue
                if not m:
                    continue

                if is_comment:
                    severity = IRRiskLevel.LOW
                else:
                    severity = fp.severity

                target_span = SourceSpan(
                    start_line=lineno,
                    end_line=lineno,
                    source_text=[line],
                )

                issues.append(ValidationIssue(
                    category=ValidationCategory.RESIDUE,
                    severity=severity,
                    message=f"{fp.message}: found '{m.group()}'",
                    field=f"residue:{fp.category.value}",
                    target_span=target_span,
                    line=lineno,
                    source_text=line,
                    suggestion=fp.suggested_action,
                ))

        return issues

    def _is_comment_line(self, stripped: str) -> bool:
        return stripped.startswith(self.comment_char)
