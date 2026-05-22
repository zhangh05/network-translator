from __future__ import annotations

from enum import Enum


class IRType(Enum):
    VLAN = "vlan"
    SVI = "svi"
    INTERFACE = "interface"
    LAG = "lag"
    STATIC_ROUTE = "static_route"
    OSPF = "ospf"
    BGP = "bgp"
    ACL = "acl"
    NAT = "nat"
    FHRP = "fhrp"
    STP = "stp"
    AAA = "aaa"
    MANAGEMENT = "management"
    ZONE = "zone"
    ADDRESS_OBJECT = "address_object"
    SERVICE_OBJECT = "service_object"
    SECURITY_POLICY = "security_policy"
    NAT_RULE = "nat_rule"
    VRF = "vrf"
    PBR = "pbr"
    IPSEC_VPN = "ipsec_vpn"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class IRFhrpProtocol(Enum):
    VRRP = "vrrp"
    HSRP = "hsrp"
    UNKNOWN = "unknown"


class IRInterfaceType(Enum):
    PHYSICAL = "physical"
    SVI = "svi"
    LOOPBACK = "loopback"
    PORT_CHANNEL = "port_channel"
    MANAGEMENT = "management"
    TUNNEL = "tunnel"
    SUBINTERFACE = "subinterface"
    NULL = "null"


class IRRiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConversionStatus(Enum):
    EXACT = "exact"
    APPROXIMATED = "approximated"
    UNSUPPORTED = "unsupported"
    NEEDS_REVIEW = "needs_review"
