from __future__ import annotations
from enum import Enum

from core.domain.base import FeatureKey

__all__ = ["FeatureKey", "FeatureSupportStatus", "ForbiddenPatternCategory"]


class FeatureSupportStatus(Enum):
    FULL = "full"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class ForbiddenPatternCategory(Enum):
    RESIDUAL_SYNTAX = "residual_syntax"
    DANGEROUS_COMMAND = "dangerous_command"
    UNSUPPORTED_FEATURE = "unsupported_feature"
    STYLE_WARNING = "style_warning"
