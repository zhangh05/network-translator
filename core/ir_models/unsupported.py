from __future__ import annotations

from dataclasses import dataclass

from core.ir_models.base import IRModelBase, SourceSpan
from core.ir_models.enums import ConversionStatus, IRRiskLevel, IRType


@dataclass
class IRUnsupported(IRModelBase):
    type: IRType
    source_span: SourceSpan
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    raw_text: str = ""
    unsupported_reason: str = ""


@dataclass
class IRUnknownBlock(IRModelBase):
    type: IRType
    source_span: SourceSpan
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    raw_text: str = ""
