import pytest
from core.vendor.base import (
    InterfaceNaming, VendorSignature, ForbiddenPattern,
    FeatureSupport, FeatureSupportStatus, ForbiddenPatternCategory,
    VendorLimitation, VendorPlatformProfile,
)
from core.domain import DeviceDomain, FeatureKey
from core.ir_models.enums import IRRiskLevel


class TestFeatureSupport:
    def test_minimal(self):
        fs = FeatureSupport(status=FeatureSupportStatus.FULL)
        assert fs.status == FeatureSupportStatus.FULL
        assert fs.notes is None
        assert fs.modes == []
        assert fs.sub_types == []

    def test_with_all_fields(self):
        fs = FeatureSupport(
            status=FeatureSupportStatus.PARTIAL,
            notes="Router-style NAT only",
            modes=["source", "destination"],
            sub_types=["standard"],
        )
        assert fs.notes == "Router-style NAT only"
        assert "source" in fs.modes


class TestForbiddenPattern:
    def test_minimal(self):
        fp = ForbiddenPattern(
            pattern=r"switchport",
            severity=IRRiskLevel.HIGH,
            category=ForbiddenPatternCategory.RESIDUAL_SYNTAX,
            message="test",
        )
        assert fp.target_context is None
        assert fp.suggested_action is None

    def test_with_context(self):
        fp = ForbiddenPattern(
            pattern=r"undo",
            severity=IRRiskLevel.HIGH,
            category=ForbiddenPatternCategory.RESIDUAL_SYNTAX,
            message="test",
            target_context="config",
            suggested_action="remove line",
        )
        assert fp.target_context == "config"
        assert fp.suggested_action == "remove line"


class TestVendorSignature:
    def test_defaults(self):
        vs = VendorSignature(pattern=r"(?i)^sysname")
        assert vs.weight == 5
        assert vs.domain is None
        assert vs.context is None

    def test_with_domain(self):
        vs = VendorSignature(pattern=r"ospf", weight=4, domain=DeviceDomain.ROUTER)
        assert vs.domain == DeviceDomain.ROUTER


class TestVendorLimitation:
    def test_minimal(self):
        vl = VendorLimitation(title="Test", description="Desc")
        assert vl.domain is None
        assert vl.risk_level is None

    def test_with_domain(self):
        vl = VendorLimitation(title="T", description="D", domain=DeviceDomain.SWITCH)
        assert vl.domain == DeviceDomain.SWITCH


class TestInterfaceNaming:
    def test_normalize_vlaninterface(self):
        """H3C Vlan-interface100 -> Vlan100"""
        n = InterfaceNaming(pattern="", svi_prefix="Vlan-interface", loopback_prefix="",
                            port_channel_prefix="", tunnel_prefix="",
                            management_prefix="", subinterface_separator=".")
        assert n.normalize("Vlan-interface100") == "Vlan100"

    def test_normalize_vlanif(self):
        """Huawei Vlanif100 -> Vlan100"""
        n = InterfaceNaming(pattern="", svi_prefix="Vlanif", loopback_prefix="",
                            port_channel_prefix="", tunnel_prefix="",
                            management_prefix="", subinterface_separator=".")
        assert n.normalize("Vlanif100") == "Vlan100"

    def test_normalize_vlan_cisco(self):
        """Cisco Vlan100 -> Vlan100"""
        n = InterfaceNaming(pattern="", svi_prefix="Vlan", loopback_prefix="",
                            port_channel_prefix="", tunnel_prefix="",
                            management_prefix="", subinterface_separator=".")
        assert n.normalize("Vlan100") == "Vlan100"

    def test_normalize_bridge_aggregation(self):
        """H3C Bridge-Aggregation1 -> PortChannel1"""
        n = InterfaceNaming(pattern="", svi_prefix="", loopback_prefix="",
                            port_channel_prefix="Bridge-Aggregation", tunnel_prefix="",
                            management_prefix="", subinterface_separator=".")
        assert n.normalize("Bridge-Aggregation1") == "PortChannel1"

    def test_normalize_eth_trunk(self):
        """Huawei Eth-Trunk1 -> PortChannel1"""
        n = InterfaceNaming(pattern="", svi_prefix="", loopback_prefix="",
                            port_channel_prefix="Eth-Trunk", tunnel_prefix="",
                            management_prefix="", subinterface_separator=".")
        assert n.normalize("Eth-Trunk1") == "PortChannel1"

    def test_normalize_port_channel(self):
        """Cisco Port-channel1 -> PortChannel1"""
        n = InterfaceNaming(pattern="", svi_prefix="", loopback_prefix="",
                            port_channel_prefix="Port-channel", tunnel_prefix="",
                            management_prefix="", subinterface_separator=".")
        assert n.normalize("Port-channel1") == "PortChannel1"

    def test_normalize_loopback(self):
        n = InterfaceNaming(pattern="", svi_prefix="", loopback_prefix="Loopback",
                            port_channel_prefix="", tunnel_prefix="",
                            management_prefix="", subinterface_separator=".")
        assert n.normalize("Loopback0") == "Loopback0"

    def test_normalize_null(self):
        n = InterfaceNaming(pattern="", svi_prefix="", loopback_prefix="",
                            port_channel_prefix="", tunnel_prefix="",
                            management_prefix="", subinterface_separator=".")
        assert n.normalize("NULL0") == "Null0"

    def test_render_svi(self):
        cisco = InterfaceNaming(pattern="", svi_prefix="Vlan", loopback_prefix="Loopback",
                                port_channel_prefix="Port-channel", tunnel_prefix="",
                                management_prefix="", subinterface_separator=".")
        result = cisco.render("Vlan100", CiscoProfile())
        assert "Vlan" in result

    def test_render_port_channel(self):
        h3c = InterfaceNaming(pattern="", svi_prefix="Vlan-interface", loopback_prefix="LoopBack",
                              port_channel_prefix="Bridge-Aggregation", tunnel_prefix="",
                              management_prefix="", subinterface_separator=".")
        result = h3c.render("PortChannel1", H3CProfile())
        assert "Bridge-Aggregation" in result


class CiscoProfile:
    interface_naming = InterfaceNaming(pattern="", svi_prefix="Vlan", loopback_prefix="Loopback",
                                       port_channel_prefix="Port-channel", tunnel_prefix="Tunnel",
                                       management_prefix="Management", subinterface_separator=".")


class H3CProfile:
    interface_naming = InterfaceNaming(pattern="", svi_prefix="Vlan-interface", loopback_prefix="LoopBack",
                                       port_channel_prefix="Bridge-Aggregation", tunnel_prefix="Tunnel",
                                       management_prefix="M-Ethernet", subinterface_separator=".")


class TestVendorPlatformProfile:
    def test_minimal(self):
        p = VendorPlatformProfile(
            key="test", vendor="test", platform="test",
            display_name="Test", device_family="unified",
            supported_domains=[DeviceDomain.SWITCH],
        )
        assert p.key == "test"
        assert p.default_domain is None
        assert p.signatures == []
        assert p.capabilities == {}
