from __future__ import annotations

import pytest

from core.ir_models.enums import (
    IRType,
    IRFhrpProtocol,
    IRInterfaceType,
    IRRiskLevel,
    ConversionStatus,
)


class TestIRType:
    def test_all_members_present(self):
        expected = {
            "VLAN", "SVI", "INTERFACE", "LAG", "STATIC_ROUTE",
            "OSPF", "BGP", "ACL", "NAT", "FHRP", "STP", "AAA",
            "MANAGEMENT", "ZONE", "ADDRESS_OBJECT", "SERVICE_OBJECT",
            "SECURITY_POLICY", "NAT_RULE", "VRF", "PBR", "IPSEC_VPN",
            "UNSUPPORTED", "UNKNOWN",
        }
        actual = {m.name for m in IRType}
        assert actual == expected, f"Missing/extra members: {expected ^ actual}"
        assert len(IRType) == 23


class TestIRFhrpProtocol:
    def test_all_members_present(self):
        assert {m.name for m in IRFhrpProtocol} == {"VRRP", "HSRP", "UNKNOWN"}
        assert len(IRFhrpProtocol) == 3


class TestIRInterfaceType:
    def test_all_members_present(self):
        expected = {
            "PHYSICAL", "SVI", "LOOPBACK", "PORT_CHANNEL",
            "MANAGEMENT", "TUNNEL", "SUBINTERFACE", "NULL",
        }
        assert {m.name for m in IRInterfaceType} == expected
        assert len(IRInterfaceType) == 8


class TestIRRiskLevel:
    def test_all_members_present(self):
        assert {m.name for m in IRRiskLevel} == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert len(IRRiskLevel) == 4

    def test_values_match_lowercase_strings(self):
        expected = {"low", "medium", "high", "critical"}
        assert {m.value for m in IRRiskLevel} == expected


class TestConversionStatus:
    def test_all_members_present(self):
        assert {m.name for m in ConversionStatus} == {
            "EXACT", "APPROXIMATED", "UNSUPPORTED", "NEEDS_REVIEW",
        }
        assert len(ConversionStatus) == 4

    def test_values_match_lowercase_strings(self):
        expected = {"exact", "approximated", "unsupported", "needs_review"}
        assert {m.value for m in ConversionStatus} == expected
