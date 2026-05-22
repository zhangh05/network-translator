from __future__ import annotations

from dataclasses import dataclass, field

from core.ir_models.base import IRModelBase, SourceSpan
from core.ir_models.enums import ConversionStatus, IRRiskLevel, IRType


@dataclass
class IROspf(IRModelBase):
    type: IRType
    source_span: SourceSpan
    process_id: int
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    router_id: str | None = None
    networks: list[dict] = field(default_factory=list)
    areas: list[dict] = field(default_factory=list)
    redistributes: list[dict] = field(default_factory=list)
    passive_interfaces: list[str] = field(default_factory=list)
    reference_bandwidth: int | None = None


@dataclass
class IRBgp(IRModelBase):
    type: IRType
    source_span: SourceSpan
    asn: int
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    router_id: str | None = None
    peers: list[dict] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    redistribute: list[str] = field(default_factory=list)


@dataclass
class IRVrf(IRModelBase):
    type: IRType
    source_span: SourceSpan
    name: str
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    rd: str | None = None
    import_rt: list[str] = field(default_factory=list)
    export_rt: list[str] = field(default_factory=list)


@dataclass
class IRPbr(IRModelBase):
    type: IRType
    source_span: SourceSpan
    name: str
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    rules: list[dict] = field(default_factory=list)


@dataclass
class IRNat(IRModelBase):
    type: IRType
    source_span: SourceSpan
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    rules: list[dict] = field(default_factory=list)


@dataclass
class IRIpsecVpn(IRModelBase):
    type: IRType
    source_span: SourceSpan
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    connections: list[dict] = field(default_factory=list)
