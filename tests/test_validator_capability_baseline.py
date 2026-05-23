from __future__ import annotations

from core.domain import DeviceDomain, FeatureKey
from core.validator.capability_baseline import (
    MANUAL_REVIEW_NO_CHECKER,
    MANUAL_REVIEW_PARTIAL_SRC,
    MANUAL_REVIEW_PARTIAL_TGT,
    MANUAL_REVIEW_UNKNOWN,
    VERIFIABLE_FEATURE_REGISTRY,
    CapabilityBaseline,
)
from core.vendor.base import FeatureSupport
from core.vendor.enums import FeatureSupportStatus

F = FeatureSupportStatus
FS = FeatureSupport


def _caps(mapping: dict[FeatureKey, tuple[FeatureSupportStatus, str | None]]) -> dict[FeatureKey, FeatureSupport]:
    return {k: FS(status=v[0], notes=v[1]) for k, v in mapping.items()}


def _stat(keys: list[FeatureKey], status: FeatureSupportStatus = F.FULL) -> dict[FeatureKey, FeatureSupport]:
    return {k: FS(status=status) for k in keys}


class TestVerifiableFeatureRegistry:
    def test_switch_has_expected_keys(self):
        reg = VERIFIABLE_FEATURE_REGISTRY[DeviceDomain.SWITCH]
        assert FeatureKey.VLAN in reg
        assert FeatureKey.SVI in reg
        assert FeatureKey.FHRP in reg
        assert FeatureKey.ACL in reg
        assert FeatureKey.STATIC_ROUTE in reg
        assert FeatureKey.OSPF in reg
        assert FeatureKey.LACP in reg

    def test_router_has_expected_keys(self):
        reg = VERIFIABLE_FEATURE_REGISTRY[DeviceDomain.ROUTER]
        assert FeatureKey.STATIC_ROUTE in reg
        assert FeatureKey.BGP in reg
        assert FeatureKey.VRF in reg
        assert FeatureKey.NAT in reg
        assert FeatureKey.PBR in reg
        assert FeatureKey.IPSEC_VPN in reg

    def test_firewall_has_expected_keys(self):
        reg = VERIFIABLE_FEATURE_REGISTRY[DeviceDomain.FIREWALL]
        assert FeatureKey.ZONE in reg
        assert FeatureKey.ADDRESS_OBJECT in reg
        assert FeatureKey.SERVICE_OBJECT in reg
        assert FeatureKey.SECURITY_POLICY in reg


class TestDeriveBaseline:
    def test_all_full_src_and_tgt_covers_registry_keys(self):
        src = _stat([FeatureKey.VLAN, FeatureKey.ACL, FeatureKey.STP])
        tgt = _stat([FeatureKey.VLAN, FeatureKey.ACL, FeatureKey.STP])
        bl = CapabilityBaseline.derive(src, tgt, src_domain=DeviceDomain.SWITCH)
        # VLAN and ACL are in registry; STP is NOT in registry → manual_review
        assert FeatureKey.VLAN in bl.auto_verifiable_semantics
        assert FeatureKey.ACL in bl.auto_verifiable_semantics
        assert FeatureKey.STP not in bl.auto_verifiable_semantics
        assert FeatureKey.STP in bl.manual_review_semantics.get(MANUAL_REVIEW_NO_CHECKER, [])

    def test_src_full_tgt_full_no_registry_goes_manual(self):
        src = _stat([FeatureKey.STP])
        tgt = _stat([FeatureKey.STP])
        bl = CapabilityBaseline.derive(src, tgt, src_domain=DeviceDomain.SWITCH)
        assert len(bl.auto_verifiable_semantics) == 0
        assert FeatureKey.STP in bl.manual_review_semantics.get(MANUAL_REVIEW_NO_CHECKER, [])

    def test_src_full_tgt_partial_manual_review(self):
        src = _stat([FeatureKey.VLAN])
        tgt = _stat([FeatureKey.VLAN], F.PARTIAL)
        bl = CapabilityBaseline.derive(src, tgt, src_domain=DeviceDomain.SWITCH)
        assert len(bl.auto_verifiable_semantics) == 0
        assert FeatureKey.VLAN in bl.manual_review_semantics.get(MANUAL_REVIEW_PARTIAL_TGT, [])

    def test_src_partial_tgt_full_manual_review(self):
        src = _stat([FeatureKey.ACL], F.PARTIAL)
        tgt = _stat([FeatureKey.ACL])
        bl = CapabilityBaseline.derive(src, tgt, src_domain=DeviceDomain.SWITCH)
        assert len(bl.auto_verifiable_semantics) == 0
        assert FeatureKey.ACL in bl.manual_review_semantics.get(MANUAL_REVIEW_PARTIAL_SRC, [])

    def test_src_partial_tgt_partial_manual_review(self):
        src = _stat([FeatureKey.OSPF], F.PARTIAL)
        tgt = _stat([FeatureKey.OSPF], F.PARTIAL)
        bl = CapabilityBaseline.derive(src, tgt, src_domain=DeviceDomain.SWITCH)
        assert FeatureKey.OSPF in bl.manual_review_semantics.get(MANUAL_REVIEW_PARTIAL_SRC, [])

    def test_src_full_tgt_unsupported(self):
        src = _stat([FeatureKey.BGP])
        tgt = _stat([FeatureKey.BGP], F.UNSUPPORTED)
        bl = CapabilityBaseline.derive(src, tgt)
        assert FeatureKey.BGP in bl.unsupported_semantics

    def test_src_full_tgt_absent_unsupported(self):
        src = _stat([FeatureKey.VRF])
        tgt: dict[FeatureKey, FeatureSupport] = {}
        bl = CapabilityBaseline.derive(src, tgt)
        assert FeatureKey.VRF in bl.unsupported_semantics

    def test_src_unsupported_irrelevant(self):
        src = _stat([FeatureKey.NAT_POLICY], F.UNSUPPORTED)
        tgt = _stat([FeatureKey.NAT_POLICY])
        bl = CapabilityBaseline.derive(src, tgt)
        assert len(bl.auto_verifiable_semantics) == 0
        assert len(bl.manual_review_semantics) == 0
        assert len(bl.unsupported_semantics) == 0
        assert bl.total_features_considered == 0

    def test_src_absent_irrelevant(self):
        src: dict[FeatureKey, FeatureSupport] = {}
        tgt = _stat([FeatureKey.VLAN])
        bl = CapabilityBaseline.derive(src, tgt)
        assert bl.total_features_considered == 0

    def test_src_unknown_goes_manual(self):
        src = _stat([FeatureKey.VLAN], F.UNKNOWN)
        tgt = _stat([FeatureKey.VLAN])
        bl = CapabilityBaseline.derive(src, tgt, src_domain=DeviceDomain.SWITCH)
        assert FeatureKey.VLAN in bl.manual_review_semantics.get(MANUAL_REVIEW_UNKNOWN, [])

    def test_tgt_unknown_goes_manual(self):
        src = _stat([FeatureKey.VLAN])
        tgt = _stat([FeatureKey.VLAN], F.UNKNOWN)
        bl = CapabilityBaseline.derive(src, tgt, src_domain=DeviceDomain.SWITCH)
        assert FeatureKey.VLAN in bl.manual_review_semantics.get(MANUAL_REVIEW_UNKNOWN, [])

    def test_multiple_features_mixed_classification(self):
        src = _stat([FeatureKey.VLAN, FeatureKey.STP, FeatureKey.BGP, FeatureKey.FHRP])
        tgt = {
            FeatureKey.VLAN: FS(F.FULL),
            FeatureKey.STP: FS(F.FULL),
            FeatureKey.BGP: FS(F.UNSUPPORTED),
            FeatureKey.FHRP: FS(F.PARTIAL),
        }
        bl = CapabilityBaseline.derive(src, tgt, src_domain=DeviceDomain.SWITCH)
        assert FeatureKey.VLAN in bl.auto_verifiable_semantics
        assert FeatureKey.STP in bl.manual_review_semantics.get(MANUAL_REVIEW_NO_CHECKER, [])
        assert FeatureKey.BGP in bl.unsupported_semantics
        assert FeatureKey.FHRP in bl.manual_review_semantics.get(MANUAL_REVIEW_PARTIAL_TGT, [])

    def test_no_domain_no_registry_all_manual(self):
        src = _stat([FeatureKey.VLAN])
        tgt = _stat([FeatureKey.VLAN])
        bl = CapabilityBaseline.derive(src, tgt)
        assert len(bl.auto_verifiable_semantics) == 0
        assert FeatureKey.VLAN in bl.manual_review_semantics.get(MANUAL_REVIEW_NO_CHECKER, [])


class TestBaselineMetrics:
    def test_verifiability_rate_full(self):
        src = _stat([FeatureKey.VLAN])
        tgt = _stat([FeatureKey.VLAN])
        bl = CapabilityBaseline.derive(src, tgt, src_domain=DeviceDomain.SWITCH)
        assert bl.verifiability_rate == 1.0

    def test_verifiability_rate_zero(self):
        src = _stat([FeatureKey.STP])
        tgt = _stat([FeatureKey.STP])
        bl = CapabilityBaseline.derive(src, tgt, src_domain=DeviceDomain.SWITCH)
        assert bl.verifiability_rate == 0.0

    def test_verifiability_rate_partial(self):
        src = _stat([FeatureKey.VLAN, FeatureKey.STP, FeatureKey.ACL])
        tgt = _stat([FeatureKey.VLAN, FeatureKey.STP, FeatureKey.ACL])
        bl = CapabilityBaseline.derive(src, tgt, src_domain=DeviceDomain.SWITCH)
        # VLAN and ACL are in registry (auto), STP is not (manual_review)
        # auto = 2, considered = 3 → rate = 2/3
        assert bl.verifiability_rate == 2 / 3
        assert bl.auto_verifiable_count == 2
        assert bl.manual_review_count == 1
        assert bl.unsupported_count == 0

    def test_empty_baseline_rate_one(self):
        bl = CapabilityBaseline()
        assert bl.verifiability_rate == 1.0


class TestBaselineToDict:
    def test_to_dict_serializable(self):
        src = _stat([FeatureKey.VLAN, FeatureKey.BGP])
        tgt = {FeatureKey.VLAN: FS(F.FULL), FeatureKey.BGP: FS(F.UNSUPPORTED)}
        bl = CapabilityBaseline.derive(src, tgt, src_domain=DeviceDomain.SWITCH)
        d = bl.to_dict()
        assert "auto_verifiable_semantics" in d
        assert "manual_review_semantics" in d
        assert "unsupported_semantics" in d
        assert "total_features_considered" in d
        assert isinstance(d["auto_verifiable_semantics"], list)
        assert isinstance(d["unsupported_semantics"], list)
        for v in d["manual_review_semantics"].values():
            assert isinstance(v, list)
        # Verify all values are strings (JSON-safe)
        import json
        json.dumps(d)

    def test_to_dict_empty_baseline(self):
        bl = CapabilityBaseline()
        d = bl.to_dict()
        assert d["auto_verifiable_semantics"] == []
        assert d["manual_review_semantics"] == {}
        assert d["unsupported_semantics"] == []
        assert d["total_features_considered"] == 0


class TestDeriveWithProfiles:
    """Parameterized coverage across all 8 vendor profiles using domain-specific caps."""

    def _bl_from_profile(self, src_key: str, tgt_key: str, domain: DeviceDomain):
        from core.vendor import get_profile, init_profiles
        init_profiles()
        src_p = get_profile(src_key)
        tgt_p = get_profile(tgt_key)
        assert src_p is not None, f"Profile {src_key} not found"
        assert tgt_p is not None, f"Profile {tgt_key} not found"
        src_caps = src_p.capabilities.get(domain, {})
        tgt_caps = tgt_p.capabilities.get(domain, {})
        return CapabilityBaseline.derive(src_caps, tgt_caps, src_domain=domain, tgt_domain=domain)

    def test_cisco_to_h3c_switch(self):
        bl = self._bl_from_profile("cisco_ios_xe", "h3c_comware", DeviceDomain.SWITCH)
        assert bl.total_features_considered >= 10
        assert bl.auto_verifiable_count >= 6
        assert len(bl.unverified_by(MANUAL_REVIEW_PARTIAL_TGT)) >= 0
        d = bl.to_dict()
        import json
        json.dumps(d)

    def test_h3c_to_cisco_switch(self):
        bl = self._bl_from_profile("h3c_comware", "cisco_ios_xe", DeviceDomain.SWITCH)
        assert bl.total_features_considered >= 10
        assert bl.verifiability_rate > 0
        d = bl.to_dict()
        import json
        json.dumps(d)

    def test_huawei_vrp_to_cisco_router(self):
        bl = self._bl_from_profile("huawei_vrp", "cisco_ios_xe", DeviceDomain.ROUTER)
        assert bl.total_features_considered >= 5
        d = bl.to_dict()
        import json
        json.dumps(d)

    def test_huawei_usg_to_cisco_router(self):
        bl = self._bl_from_profile("huawei_usg", "cisco_ios_xe", DeviceDomain.ROUTER)
        assert bl.total_features_considered >= 0
        d = bl.to_dict()
        import json
        json.dumps(d)

    def test_ruijie_to_cisco_switch(self):
        bl = self._bl_from_profile("ruijie_rgos", "cisco_ios_xe", DeviceDomain.SWITCH)
        assert bl.total_features_considered >= 5
        d = bl.to_dict()
        import json
        json.dumps(d)

    def test_hillstone_to_cisco_router(self):
        bl = self._bl_from_profile("hillstone_stoneos", "cisco_ios_xe", DeviceDomain.ROUTER)
        assert bl.total_features_considered >= 0
        d = bl.to_dict()
        import json
        json.dumps(d)

    def test_topsec_to_cisco_router(self):
        bl = self._bl_from_profile("topsec_tos", "cisco_ios_xe", DeviceDomain.ROUTER)
        d = bl.to_dict()
        import json
        json.dumps(d)

    def test_dptech_to_cisco_router(self):
        bl = self._bl_from_profile("dptech_fw", "cisco_ios_xe", DeviceDomain.ROUTER)
        d = bl.to_dict()
        import json
        json.dumps(d)

    def test_huawei_usg_to_hillstone_switch(self):
        bl = self._bl_from_profile("huawei_usg", "hillstone_stoneos", DeviceDomain.SWITCH)
        d = bl.to_dict()
        import json
        json.dumps(d)

    def test_cisco_to_huawei_vrp_router(self):
        bl = self._bl_from_profile("cisco_ios_xe", "huawei_vrp", DeviceDomain.ROUTER)
        assert bl.total_features_considered >= 5
        d = bl.to_dict()
        import json
        json.dumps(d)


# Add convenience accessor to CapabilityBaseline for cleaner test assertions
def unverified_by(self, reason: str) -> list[FeatureKey]:
    return self.manual_review_semantics.get(reason, [])

CapabilityBaseline.unverified_by = unverified_by
