from __future__ import annotations

from dataclasses import dataclass, field

from core.ir_models.base import IRModelBase, SourceSpan
from core.ir_models.enums import ConversionStatus, IRInterfaceType, IRRiskLevel, IRType


@dataclass
class IRInterface(IRModelBase):
    type: IRType
    source_span: SourceSpan
    iftype: IRInterfaceType
    name: str
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    description: str | None = None
    ip: str | None = None
    mask: str | None = None
    untagged_vlan: int | None = None
    trunk_allowed: list[int] | None = None
    trunk_allowed_all: bool = False
    lag_group: int | None = None
    speed: str | None = None
    duplex: str | None = None
    shutdown: bool = False


@dataclass
class IRStaticRoute(IRModelBase):
    type: IRType
    source_span: SourceSpan
    prefix: str
    mask: str
    nexthop: str
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    metric: int | None = None
    vrf: str | None = None
    tag: int | None = None
    description: str | None = None
    distance: int | None = None


@dataclass
class IRAclEntry:
    action: str
    sequence: int | None = None
    protocol: str | None = None
    src: str | None = None
    src_wildcard: str | None = None
    src_port: str | None = None
    dst: str | None = None
    dst_wildcard: str | None = None
    dst_port: str | None = None
    remark: str | None = None
    established: bool = False
    logging: bool = False


@dataclass
class IRAcl(IRModelBase):
    type: IRType
    source_span: SourceSpan
    acl_type: str
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    number: int | None = None
    name: str | None = None
    entries: list[IRAclEntry] = field(default_factory=list)
    applied_to: list[dict] = field(default_factory=list)


@dataclass
class IRAaa(IRModelBase):
    type: IRType
    source_span: SourceSpan
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    auth_method: str | None = None
    accounting: str | None = None
    servers: list[dict] = field(default_factory=list)


@dataclass
class IRManagement(IRModelBase):
    type: IRType
    source_span: SourceSpan
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
    snmp: list[dict] = field(default_factory=list)
    ntp: list[dict] = field(default_factory=list)
    syslog: list[dict] = field(default_factory=list)
    ssh: dict | None = None
    dns: dict | None = None
