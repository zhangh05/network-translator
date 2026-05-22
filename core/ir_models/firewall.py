from __future__ import annotations

from dataclasses import dataclass, field

from core.ir_models.base import IRModelBase, SourceSpan
from core.ir_models.enums import ConversionStatus, IRRiskLevel, IRType


@dataclass
class IRZone(IRModelBase):
    type: IRType
    source_span: SourceSpan
    name: str
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    members: list[str] = field(default_factory=list)


@dataclass
class IRAddressObject(IRModelBase):
    type: IRType
    source_span: SourceSpan
    name: str
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    ip: str | None = None
    network: str | None = None
    range: str | None = None
    fqdn: str | None = None


@dataclass
class IRServiceObject(IRModelBase):
    type: IRType
    source_span: SourceSpan
    name: str
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    protocol: str | None = None
    port: str | None = None
    port_range: str | None = None


@dataclass
class IRSecurityPolicy(IRModelBase):
    type: IRType
    source_span: SourceSpan
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    name: str | None = None
    from_zone: str | None = None
    to_zone: str | None = None
    src_addresses: list[str] = field(default_factory=list)
    dst_addresses: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    action: str = "permit"
    logging: bool = False
    session_stateful: bool = True
    description: str | None = None


@dataclass
class IRNatRule(IRModelBase):
    type: IRType
    source_span: SourceSpan
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    name: str | None = None
    original_ip: str | None = None
    translated_ip: str | None = None
    pool: str | None = None
    interface: str | None = None
    from_zone: str | None = None
    to_zone: str | None = None
    src_address: str | None = None
    dst_address: str | None = None
    service: str | None = None
    nat_type: str = "source"
