from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from core.ir_models.enums import IRType


class DeviceDomain(Enum):
    SWITCH = "switch"
    ROUTER = "router"
    FIREWALL = "firewall"


class FeatureKey(Enum):
    VLAN = "vlan"
    SVI = "svi"
    TRUNK = "trunk"
    STP = "stp"
    LACP = "lacp"
    FHRP = "fhrp"
    LLDP = "lldp"
    CDP = "cdp"
    DHCP_SNOOPING = "dhcp_snooping"
    STATIC_ROUTE = "static_route"
    OSPF = "ospf"
    BGP = "bgp"
    VRF = "vrf"
    PBR = "pbr"
    ACL = "acl"
    NAT = "nat"
    NAT_POLICY = "nat_policy"
    INTERFACE = "interface"
    MANAGEMENT = "management"
    AAA = "aaa"
    IPSEC_VPN = "ipsec_vpn"
    ZONE = "zone"
    ADDRESS_OBJECT = "address_object"
    SERVICE_OBJECT = "service_object"
    SECURITY_POLICY = "security_policy"
    HA = "ha"
    USER_AUTH = "user_auth"
    LOGGING = "logging"
    MANAGEMENT_ACCESS = "management_access"


@dataclass
class DomainProfile:
    domain: DeviceDomain
    description: str
    required_ir_types: list[IRType]
    optional_ir_types: list[IRType]
    feature_keys: list[FeatureKey]
    critical_validators: list[str]
    coverage_thresholds: dict[str, float]
    notes: list[str] = field(default_factory=list)
