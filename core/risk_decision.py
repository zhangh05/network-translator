from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional


class RiskSeverity:
    INFO = "info"
    WARNING = "warning"
    FATAL = "fatal"


class RiskSource:
    ANALYZER = "analyzer"
    VALIDATOR = "validator"
    CAPABILITY = "capability"
    CONSISTENCY = "consistency"
    LLM = "llm"
    MANUAL_REVIEW = "manual_review"
    PLATFORM = "platform"
    CONTENT = "content"


HIGH_RISK_FEATURES = {"nat", "acl", "ipsec", "route_policy", "security_policy"}


@dataclass
class RiskSignal:
    source: str
    feature: str
    severity: str
    message: str
    deployability_impact: bool = False
    manual_review_impact: bool = False

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "feature": self.feature,
            "severity": self.severity,
            "message": self.message,
            "deployability_impact": self.deployability_impact,
            "manual_review_impact": self.manual_review_impact,
        }


@dataclass
class RiskDecision:
    deployable: bool
    manual_review_required: bool
    signals: List[RiskSignal] = field(default_factory=list)
    validation_level: str = RiskSeverity.INFO

    def to_dict(self) -> dict:
        return {
            "deployable": self.deployable,
            "manual_review_required": self.manual_review_required,
            "validation_level": self.validation_level,
            "signals": [s.to_dict() for s in self.signals],
        }

    def has_signal_from(self, source: str) -> bool:
        return any(s.source == source for s in self.signals)

    def has_feature_signal(self, feature: str) -> bool:
        return any(s.feature == feature for s in self.signals)


def _max_severity(signals: List[RiskSignal]) -> str:
    if any(s.severity == RiskSeverity.FATAL for s in signals):
        return RiskSeverity.FATAL
    if any(s.severity == RiskSeverity.WARNING for s in signals):
        return RiskSeverity.WARNING
    return RiskSeverity.INFO


def decide_deployability(
    signals: List[RiskSignal],
    features: Optional[List[str]] = None,
) -> RiskDecision:
    features = features or []
    signals = [s for s in signals if s.feature != "_meta"]

    fatal_signals = [s for s in signals if s.severity == RiskSeverity.FATAL]
    warning_signals = [s for s in signals if s.severity == RiskSeverity.WARNING]
    content_fatal = any(s.source == RiskSource.CONTENT and s.severity == RiskSeverity.FATAL for s in signals)
    content_critical = any(s.source == RiskSource.CONTENT and s.severity == RiskSeverity.WARNING for s in signals)
    has_high_risk_consistency = any(
        s.source == RiskSource.CONSISTENCY
        and s.feature in HIGH_RISK_FEATURES
        and s.severity in (RiskSeverity.WARNING, RiskSeverity.FATAL)
        for s in signals
    )
    has_high_risk_analyzer = any(
        s.source == RiskSource.ANALYZER
        and s.feature in HIGH_RISK_FEATURES
        and s.severity in (RiskSeverity.WARNING, RiskSeverity.FATAL)
        for s in signals
    )
    has_capability_gap = any(
        s.source == RiskSource.CAPABILITY and s.severity in (RiskSeverity.WARNING, RiskSeverity.FATAL)
        for s in signals
    )
    has_manual_review_marker = any(s.source == RiskSource.MANUAL_REVIEW for s in signals)
    has_platform_residue = any(
        s.source == RiskSource.PLATFORM
        and s.severity in (RiskSeverity.WARNING, RiskSeverity.FATAL)
        and s.deployability_impact
        for s in signals
    )

    has_high_risk_warning = has_high_risk_consistency or has_high_risk_analyzer

    validation_level = _max_severity(signals)
    if fatal_signals or content_fatal:
        validation_level = RiskSeverity.FATAL
        return RiskDecision(
            deployable=False,
            manual_review_required=True,
            validation_level=RiskSeverity.FATAL,
            signals=signals,
        )

    if has_high_risk_warning or has_capability_gap or has_platform_residue or has_manual_review_marker or content_critical:
        return RiskDecision(
            deployable=False,
            manual_review_required=True,
            validation_level=RiskSeverity.WARNING,
            signals=signals,
        )

    if warning_signals:
        return RiskDecision(
            deployable=True,
            manual_review_required=True,
            validation_level=RiskSeverity.WARNING,
            signals=signals,
        )

    return RiskDecision(
        deployable=True,
        manual_review_required=False,
        validation_level=RiskSeverity.INFO,
        signals=signals,
    )
