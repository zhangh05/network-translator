from __future__ import annotations

from dataclasses import dataclass, field

from core.ir_models.enums import ConversionStatus, IRRiskLevel, IRType


@dataclass(frozen=True)
class SourceSpan:
    start_line: int
    end_line: int
    source_text: list[str] = field(default_factory=list)


@dataclass
class IRModelBase:
    type: IRType
    source_span: SourceSpan
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
