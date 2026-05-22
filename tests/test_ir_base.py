from __future__ import annotations

import pytest
from core.ir_models import (
    ConversionStatus,
    IRConfig,
    IRConfigMeta,
    IRModelBase,
    IRRiskLevel,
    IRType,
    SourceSpan,
)
from core.domain import DeviceDomain


class TestSourceSpan:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=5)
        assert span.start_line == 1
        assert span.end_line == 5
        assert span.source_text == []

    def test_with_source_text(self):
        span = SourceSpan(start_line=1, end_line=1, source_text=["vlan 10"])
        assert span.source_text == ["vlan 10"]

    def test_frozen(self):
        span = SourceSpan(start_line=1, end_line=1)
        with pytest.raises(AttributeError):
            span.start_line = 99


class TestIRModelBase:
    def test_is_class(self):
        assert isinstance(IRModelBase, type)

    def test_subclass_of_ir_model_base(self):
        from core.ir_models import IRVlan
        assert issubclass(IRVlan, IRModelBase)


class TestConversionStatus:
    def test_values(self):
        assert ConversionStatus.EXACT.value == "exact"
        assert ConversionStatus.APPROXIMATED.value == "approximated"
        assert ConversionStatus.UNSUPPORTED.value == "unsupported"
        assert ConversionStatus.NEEDS_REVIEW.value == "needs_review"


class TestIRConfigMeta:
    def test_minimal(self):
        meta = IRConfigMeta(
            source_vendor="h3c",
            target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH,
            target_domain=DeviceDomain.SWITCH,
            source_platform="comware",
            target_platform="ios_xe",
        )
        assert meta.source_vendor == "h3c"
        assert meta.target_vendor == "cisco"

    def test_with_hostname(self):
        meta = IRConfigMeta(
            source_vendor="h3c",
            target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH,
            target_domain=DeviceDomain.SWITCH,
            source_platform="comware",
            target_platform="ios_xe",
            hostname="SW01",
        )
        assert meta.hostname == "SW01"

    def test_with_detected_domains(self):
        meta = IRConfigMeta(
            source_vendor="h3c",
            target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH,
            target_domain=DeviceDomain.SWITCH,
            source_platform="comware",
            target_platform="ios_xe",
            detected_domains=[DeviceDomain.SWITCH],
            domain_confidence=0.95,
        )
        assert DeviceDomain.SWITCH in meta.detected_domains
        assert meta.domain_confidence == 0.95

    def test_domain_evidence(self):
        meta = IRConfigMeta(
            source_vendor="h3c",
            target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH,
            target_domain=DeviceDomain.SWITCH,
            source_platform="comware",
            target_platform="ios_xe",
            domain_evidence={"vlan": 0.9, "stp": 0.7},
        )
        assert meta.domain_evidence["vlan"] == 0.9

    def test_manual_domain_override(self):
        meta = IRConfigMeta(
            source_vendor="h3c",
            target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH,
            target_domain=DeviceDomain.SWITCH,
            source_platform="comware",
            target_platform="ios_xe",
            manual_domain_override=DeviceDomain.ROUTER,
        )
        assert meta.manual_domain_override == DeviceDomain.ROUTER

    def test_platform_version(self):
        meta = IRConfigMeta(
            source_vendor="h3c",
            target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH,
            target_domain=DeviceDomain.SWITCH,
            source_platform="comware",
            target_platform="ios_xe",
            platform="H3C S6850",
            version="7.1.070",
        )
        assert meta.platform == "H3C S6850"
        assert meta.version == "7.1.070"

    def test_warnings_assumptions(self):
        meta = IRConfigMeta(
            source_vendor="h3c",
            target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH,
            target_domain=DeviceDomain.SWITCH,
            source_platform="comware",
            target_platform="ios_xe",
            warnings=["missing interface config"],
            assumptions=["STP enabled by default"],
        )
        assert "missing interface config" in meta.warnings
        assert "STP enabled by default" in meta.assumptions


class TestIRConfig:
    def test_minimal(self):
        meta = IRConfigMeta(
            source_vendor="h3c",
            target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH,
            target_domain=DeviceDomain.SWITCH,
            source_platform="comware",
            target_platform="ios_xe",
        )
        config = IRConfig(meta=meta)
        assert config.meta == meta
        assert config.interfaces == []
        assert config.vlans == []
