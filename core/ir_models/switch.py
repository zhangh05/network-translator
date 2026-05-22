from __future__ import annotations

from dataclasses import dataclass, field

from core.ir_models.base import IRModelBase, SourceSpan
from core.ir_models.enums import ConversionStatus, IRFhrpProtocol, IRRiskLevel, IRType


@dataclass
class IRVlan(IRModelBase):
    type: IRType
    source_span: SourceSpan
    vid: int
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    name: str | None = None


@dataclass
class IRFhrp(IRModelBase):
    type: IRType
    source_span: SourceSpan
    protocol: IRFhrpProtocol
    group_id: int
    virtual_ip: str
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    priority: int = 100
    preempt: bool = False
    track: list[dict] = field(default_factory=list)
    authentication: str | None = None


@dataclass
class IRSvi(IRModelBase):
    type: IRType
    source_span: SourceSpan
    vid: int
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    ip: str | None = None
    mask: str | None = None
    fhrp: list[IRFhrp] = field(default_factory=list)
    acl_in: str | None = None
    acl_out: str | None = None
    description: str | None = None
    shutdown: bool = False


@dataclass
class IRLag(IRModelBase):
    type: IRType
    source_span: SourceSpan
    lag_id: int
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    member_ports: list[str] = field(default_factory=list)
    mode: str = "static"
    lacp_mode: str = "active"


@dataclass
class IRStp(IRModelBase):
    type: IRType
    source_span: SourceSpan
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    mode: str | None = None
    region: str | None = None
    revision: int | None = None
    instances: list[dict] = field(default_factory=list)
    priority: dict = field(default_factory=dict)
