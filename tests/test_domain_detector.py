import pytest
from core.domain import DomainDetector, DeviceDomain, FeatureKey


class TestDomainDetector:
    def test_detect_switch_from_switchport(self):
        detector = DomainDetector()
        config = "vlan 10\n switchport mode trunk\n spanning-tree mode rstp"
        result = detector.detect(config)
        assert result.primary_domain == DeviceDomain.SWITCH
        assert result.confidence > 0.5

    def test_detect_router_from_ospf(self):
        detector = DomainDetector()
        config = "router ospf 1\n network 10.0.0.0 0.255.255.255 area 0"
        result = detector.detect(config)
        assert result.primary_domain == DeviceDomain.ROUTER

    def test_detect_firewall_from_security_zone(self):
        detector = DomainDetector()
        config = "security-zone name trust\n import interface GigabitEthernet0/1"
        result = detector.detect(config)
        assert result.primary_domain == DeviceDomain.FIREWALL

    def test_l3_switch_with_ospf_stays_switch(self):
        """L3 switch with strong switch signals + routing should still be SWITCH."""
        detector = DomainDetector()
        config = "\n".join([
            "vlan batch 10 20 30",
            "interface GigabitEthernet0/1",
            " port link-type trunk",
            " port trunk permit vlan all",
            " spanning-tree enable",
            "interface Vlan-interface10",
            " ip address 10.0.10.1 255.255.255.0",
            "router ospf 1",
            " network 10.0.0.0 0.255.255.255 area 0",
        ])
        result = detector.detect(config)
        assert result.primary_domain == DeviceDomain.SWITCH
        # OSPF should be in secondary_features, not in primary (SWITCH) detected
        assert any(fk == FeatureKey.OSPF for fk in result.secondary_features)
        assert result.confidence > 0.5

    def test_router_no_switch_features(self):
        """Pure router config should detect as ROUTER."""
        detector = DomainDetector()
        config = "\n".join([
            "router bgp 65001",
            " bgp router-id 1.1.1.1",
            " neighbor 10.0.0.1 remote-as 65002",
            "ip route 0.0.0.0 0.0.0.0 10.0.0.1",
        ])
        result = detector.detect(config)
        assert result.primary_domain == DeviceDomain.ROUTER
        assert result.confidence > 0.5

    def test_empty_config_defaults_to_switch(self):
        detector = DomainDetector()
        result = detector.detect("! empty config\n")
        assert result.primary_domain == DeviceDomain.SWITCH
        assert result.confidence == 0.0

    def test_returns_evidence_dict(self):
        detector = DomainDetector()
        result = detector.detect("interface Vlan-interface10")
        assert isinstance(result.evidence, dict)
        assert "switch" in result.evidence or result.evidence == {}

    def test_vendor_hint_accepted(self):
        """verify vendor_hint parameter is accepted without error."""
        detector = DomainDetector()
        result = detector.detect("router ospf 1", vendor_hint="cisco")
        assert result.primary_domain is not None

    def test_detected_features_are_featurekey_enums(self):
        detector = DomainDetector()
        config = "vlan 10\n switchport mode trunk\n spanning-tree enable"
        result = detector.detect(config)
        for fk in result.detected_features:
            assert isinstance(fk, FeatureKey)

    def test_secondary_features_populated(self):
        """When switch has routing features, secondary_features should have them."""
        detector = DomainDetector()
        config = "\n".join([
            "vlan 10",
            " switchport access vlan 10",
            " spanning-tree mode rstp",
            "router ospf 1",
            " network 10.0.0.0 0.255.255.255 area 0",
            "router bgp 65001",
        ])
        result = detector.detect(config)
        assert result.primary_domain == DeviceDomain.SWITCH
        assert len(result.secondary_features) >= 2  # OSPF + BGP
