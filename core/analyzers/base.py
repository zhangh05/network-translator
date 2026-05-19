from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class FeatureAnalysis:
    feature: str
    status: str = "skipped"
    risk_level: str = "info"
    manual_review_required: bool = False
    rules: list = field(default_factory=list)
    references: Dict[str, Any] = field(default_factory=dict)
    missing_context: List[str] = field(default_factory=list)
    source_lines: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class FeatureAnalyzer(ABC):
    @abstractmethod
    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        pass

    @property
    @abstractmethod
    def feature_name(self) -> str:
        pass
