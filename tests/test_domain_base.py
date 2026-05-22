import pytest
from core.domain import DeviceDomain, DomainProfile, FeatureKey
from core.ir_models.enums import IRType


class TestDeviceDomain:
    def test_switch(self):
        assert DeviceDomain.SWITCH.value == "switch"

    def test_router(self):
        assert DeviceDomain.ROUTER.value == "router"

    def test_firewall(self):
        assert DeviceDomain.FIREWALL.value == "firewall"

    def test_three_members(self):
        assert len(DeviceDomain) == 3


class TestFeatureKey:
    def test_vlan(self):
        assert FeatureKey.VLAN.value == "vlan"

    def test_svi(self):
        assert FeatureKey.SVI.value == "svi"

    def test_trunk(self):
        assert FeatureKey.TRUNK.value == "trunk"

    def test_total_members(self):
        assert len(FeatureKey) == 29


class TestDomainProfile:
    def test_minimal(self):
        profile = DomainProfile(
            domain=DeviceDomain.SWITCH,
            description="test",
            required_ir_types=[IRType.VLAN, IRType.INTERFACE],
            optional_ir_types=[IRType.OSPF],
            feature_keys=[FeatureKey.VLAN],
            critical_validators=["residue", "coverage"],
            coverage_thresholds={"vlans": 1.0},
        )
        assert profile.domain == DeviceDomain.SWITCH
        assert profile.description == "test"
        assert profile.notes == []

    def test_notes_default(self):
        profile = DomainProfile(
            domain=DeviceDomain.SWITCH,
            description="test",
            required_ir_types=[],
            optional_ir_types=[],
            feature_keys=[],
            critical_validators=[],
            coverage_thresholds={},
        )
        assert profile.notes == []

    def test_with_notes(self):
        profile = DomainProfile(
            domain=DeviceDomain.ROUTER,
            description="router test",
            required_ir_types=[IRType.OSPF],
            optional_ir_types=[IRType.BGP],
            feature_keys=[FeatureKey.OSPF],
            critical_validators=["residue"],
            coverage_thresholds={"ospf": 1.0},
            notes=["OSPF area format may differ across vendors"],
        )
        assert len(profile.notes) == 1
        assert "OSPF" in profile.notes[0]
