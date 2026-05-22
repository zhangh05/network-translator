from __future__ import annotations

from dataclasses import dataclass, field

from core.ir_models.enums import ConversionStatus, IRRiskLevel, IRType


@dataclass(frozen=True)
class SourceSpan:
    start_line: int
    end_line: int
    source_text: list[str] = field(default_factory=list)


class IRModelBase:
    """Marker / mixin base for IR model dataclasses.

    Subclasses define their own @dataclass fields independently
    (type, source_span, conversion_status, reason, risk_level, review_notes)
    to avoid Python 3.9 dataclass inheritance ordering issues.
    """
