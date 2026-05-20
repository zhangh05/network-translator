"""P0-1/P0-2: Unified Risk Decision Model tests."""
import pytest
from core.risk_decision import (
    RiskSignal, RiskSeverity, RiskSource, RiskDecision,
    decide_deployability, HIGH_RISK_FEATURES,
)
from core.graph.nodes import ValidateNode

node = ValidateNode()


# ═══════════════════════════════════════════════════════════════════
# RiskSignal creation
# ═══════════════════════════════════════════════════════════════════

class TestRiskSignal:
    def test_create_risk_signal(self):
        s = RiskSignal(source=RiskSource.ANALYZER, feature="nat",
                       severity=RiskSeverity.WARNING, message="missing refs",
                       deployability_impact=True, manual_review_impact=True)
        assert s.source == "analyzer"
        assert s.feature == "nat"
        assert s.severity == "warning"
        assert s.to_dict()["source"] == "analyzer"

    def test_risk_signal_to_dict_roundtrip(self):
        s = RiskSignal(source=RiskSource.VALIDATOR, feature="acl",
                       severity=RiskSeverity.FATAL, message="platform residue",
                       deployability_impact=True, manual_review_impact=True)
        d = s.to_dict()
        assert d["source"] == "validator"
        assert d["feature"] == "acl"
        assert d["severity"] == "fatal"


# ═══════════════════════════════════════════════════════════════════
# decide_deployability — no signals
# ═══════════════════════════════════════════════════════════════════

class TestDecideNoSignals:
    """No risk signals → deployable=true, no manual review."""

    def test_no_signals(self):
        d = decide_deployability([])
        assert d.deployable
        assert not d.manual_review_required
        assert d.validation_level == "info"

    def test_no_signals_with_high_risk_feature(self):
        """Even with high-risk features listed, no signals → deployable=true."""
        d = decide_deployability([], features=["nat", "acl"])
        assert d.deployable, "High-risk feature alone without signals must not force deployable=false"
        assert not d.manual_review_required


# ═══════════════════════════════════════════════════════════════════
# decide_deployability — fatal signals
# ═══════════════════════════════════════════════════════════════════

class TestDecideFatal:
    def test_fatal_signal(self):
        signals = [
            RiskSignal(RiskSource.CONTENT, "content", RiskSeverity.FATAL,
                       "翻译结果为空", True, True),
        ]
        d = decide_deployability(signals)
        assert not d.deployable
        assert d.manual_review_required
        assert d.validation_level == "fatal"

    def test_fatal_analyzer_signal(self):
        signals = [
            RiskSignal(RiskSource.ANALYZER, "nat", RiskSeverity.FATAL,
                       "NAT 致命错误", True, True),
        ]
        d = decide_deployability(signals, features=["nat"])
        assert not d.deployable
        assert d.manual_review_required


# ═══════════════════════════════════════════════════════════════════
# decide_deployability — high-risk consistency failure
# ═══════════════════════════════════════════════════════════════════

class TestDecideHighRiskConsistency:
    def test_nat_consistency_missing(self):
        signals = [
            RiskSignal(RiskSource.CONSISTENCY, "nat", RiskSeverity.WARNING,
                       "NAT consistency failure", True, True),
        ]
        d = decide_deployability(signals)
        assert not d.deployable, "NAT consistency failure → deployable=false"
        assert d.manual_review_required

    def test_acl_consistency_missing(self):
        signals = [
            RiskSignal(RiskSource.CONSISTENCY, "acl", RiskSeverity.WARNING,
                       "ACL consistency failure", True, True),
        ]
        d = decide_deployability(signals)
        assert not d.deployable

    def test_ipsec_consistency_missing(self):
        signals = [
            RiskSignal(RiskSource.CONSISTENCY, "ipsec", RiskSeverity.WARNING,
                       "IPsec consistency failure", True, True),
        ]
        d = decide_deployability(signals)
        assert not d.deployable

    def test_route_policy_consistency_missing(self):
        signals = [
            RiskSignal(RiskSource.CONSISTENCY, "route_policy", RiskSeverity.WARNING,
                       "Route-policy consistency failure", True, True),
        ]
        d = decide_deployability(signals)
        assert not d.deployable

    def test_security_policy_consistency_missing(self):
        signals = [
            RiskSignal(RiskSource.CONSISTENCY, "security_policy", RiskSeverity.WARNING,
                       "Security-policy consistency failure", True, True),
        ]
        d = decide_deployability(signals)
        assert not d.deployable


# ═══════════════════════════════════════════════════════════════════
# decide_deployability — MANUAL_REVIEW marker
# ═══════════════════════════════════════════════════════════════════

class TestDecideManualReviewMarker:
    def test_manual_review_in_output(self):
        signals = [
            RiskSignal(RiskSource.MANUAL_REVIEW, "output", RiskSeverity.WARNING,
                       "MANUAL_REVIEW 标记", True, True),
        ]
        d = decide_deployability(signals)
        assert not d.deployable
        assert d.manual_review_required


# ═══════════════════════════════════════════════════════════════════
# decide_deployability — platform residue
# ═══════════════════════════════════════════════════════════════════

class TestDecidePlatformResidue:
    def test_residue_in_output(self):
        signals = [
            RiskSignal(RiskSource.PLATFORM, "platform", RiskSeverity.WARNING,
                       "源厂商残留 — import-route", True, True),
        ]
        d = decide_deployability(signals)
        assert not d.deployable
        assert d.manual_review_required


# ═══════════════════════════════════════════════════════════════════
# decide_deployability — capability gap
# ═══════════════════════════════════════════════════════════════════

class TestDecideCapabilityGap:
    def test_unsupported_feature_gap(self):
        signals = [
            RiskSignal(RiskSource.CAPABILITY, "lacp", RiskSeverity.WARNING,
                       "目标厂商不支持此功能", True, True),
        ]
        d = decide_deployability(signals)
        assert not d.deployable
        assert d.manual_review_required

    def test_unknown_feature_gap(self):
        signals = [
            RiskSignal(RiskSource.CAPABILITY, "dhcp", RiskSeverity.WARNING,
                       "知识库未确认", True, True),
        ]
        d = decide_deployability(signals)
        assert not d.deployable
        assert d.manual_review_required


# ═══════════════════════════════════════════════════════════════════
# decide_deployability — ordinary warnings
# ═══════════════════════════════════════════════════════════════════

class TestDecideOrdinaryWarnings:
    def test_non_high_risk_warning(self):
        signals = [
            RiskSignal(RiskSource.VALIDATOR, "interface", RiskSeverity.WARNING,
                       "接口命名建议调整", False, False),
        ]
        d = decide_deployability(signals)
        assert d.deployable, "Low-risk warning → deployable=true"
        assert d.manual_review_required, "Low-risk warning → manual review"


# ═══════════════════════════════════════════════════════════════════
# ValidateNode._evaluate_deployability backward compatibility
# ═══════════════════════════════════════════════════════════════════

class TestBackwardCompatDeployability:
    """Old _evaluate_deployability path still works (no categorical high-risk check)."""

    def test_old_api_fatal(self):
        dep = node._evaluate_deployability("fatal", False, False)
        assert not dep["deployable"]
        assert dep["manual_review_required"]

    def test_old_api_high_risk_warning(self):
        dep = node._evaluate_deployability("warning", True, False, features=["nat"])
        assert not dep["deployable"]

    def test_old_api_critical_content(self):
        dep = node._evaluate_deployability("warning", False, True, features=["nat"])
        assert not dep["deployable"]

    def test_old_api_warning_level(self):
        dep = node._evaluate_deployability("warning", False, False)
        assert dep["deployable"]
        assert dep["manual_review_required"]

    def test_old_api_info_level(self):
        dep = node._evaluate_deployability("info", False, False)
        assert dep["deployable"]
        assert not dep["manual_review_required"]


# ═══════════════════════════════════════════════════════════════════
# Integration: ValidateNode._collect_risk_signals
# ═══════════════════════════════════════════════════════════════════

class TestCollectRiskSignals:
    def test_analyzer_signal_injection(self):
        state = type("S", (), {"get": lambda s, k, d=None: {
            "config_text": "ip nat inside source list 10 pool P overload\n",
            "from_vendor": "cisco",
            "to_vendor": "huawei",
            "features": ["nat"],
            "analyzer_results": [
                {"feature": "nat", "status": "analyzed",
                 "risk_level": "warning", "summary": "missing NAT reference",
                 "source_lines": [], "details": {}}
            ],
            "capability_gaps": [],
            "capability_gap_severity": "info",
        }.get(k, d)})()
        result = type("R", (), {"valid": True, "errors": [], "warnings": []})()
        risk_info = node._collect_risk_signals(
            state, result,
            config_content="ip nat inside source list 10 pool P overload",
            source_config="ip nat inside source list 10 pool P overload",
            to_vendor="huawei",
            features=["nat"],
        )
        signals = risk_info["signals"]
        analyzer_signals = [s for s in signals if s["source"] == "analyzer"]
        assert len(analyzer_signals) > 0
        assert any(s["feature"] == "nat" for s in analyzer_signals)

    def test_clean_config_no_signals(self):
        state = type("S", (), {"get": lambda s, k, d=None: {
            "config_text": "hostname R1\n!\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.0.0.0\n no shutdown\n",
            "from_vendor": "cisco",
            "to_vendor": "cisco",
            "features": ["system", "interface"],
            "analyzer_results": [],
            "capability_gaps": [],
            "capability_gap_severity": "info",
        }.get(k, d)})()
        result = type("R", (), {"valid": True, "errors": [], "warnings": []})()
        risk_info = node._collect_risk_signals(
            state, result,
            config_content="hostname R1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.0.0.0\n no shutdown",
            source_config="hostname R1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.0.0.0\n no shutdown",
            to_vendor="cisco",
            features=["system", "interface"],
        )
        fatal_sigs = [s for s in risk_info["signals"] if s["severity"] == "fatal"]
        assert len(fatal_sigs) == 0, f"Clean config should have no fatal signals: {fatal_sigs}"


# ═══════════════════════════════════════════════════════════════════
# Verify HIGH_RISK_FEATURES set
# ═══════════════════════════════════════════════════════════════════

def test_high_risk_features():
    assert "nat" in HIGH_RISK_FEATURES
    assert "acl" in HIGH_RISK_FEATURES
    assert "ipsec" in HIGH_RISK_FEATURES
    assert "route_policy" in HIGH_RISK_FEATURES
    assert "security_policy" in HIGH_RISK_FEATURES
    assert len(HIGH_RISK_FEATURES) == 5


# ═══════════════════════════════════════════════════════════════════
# RiskDecision.to_dict API contract
# ═══════════════════════════════════════════════════════════════════

def test_risk_decision_to_dict():
    d = RiskDecision(deployable=False, manual_review_required=True,
                     validation_level="fatal", signals=[
                         RiskSignal("analyzer", "nat", "fatal", "err", True, True),
                     ])
    dd = d.to_dict()
    assert dd["deployable"] is False
    assert dd["manual_review_required"] is True
    assert dd["validation_level"] == "fatal"
    assert len(dd["signals"]) == 1
    assert dd["signals"][0]["source"] == "analyzer"
