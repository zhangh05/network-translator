from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.domain import DeviceDomain, FeatureKey
from core.vendor.base import FeatureSupport
from core.vendor.enums import FeatureSupportStatus

VERIFIABLE_FEATURE_REGISTRY: dict[DeviceDomain, set[FeatureKey]] = {
    DeviceDomain.SWITCH: {
        # OSPF removed from registry — current SemanticValidator only checks
        # conversion_status, not OSPF semantic equivalence (area, cost, NSSA).
        # Re-add when deep OSPF checker is implemented (Phase 6 P0 candidate).
        FeatureKey.VLAN,
        FeatureKey.SVI,
        FeatureKey.FHRP,
        FeatureKey.ACL,
        FeatureKey.STATIC_ROUTE,
        FeatureKey.LACP,
    },
    DeviceDomain.ROUTER: {
        FeatureKey.STATIC_ROUTE,
        FeatureKey.BGP,
        FeatureKey.VRF,
        FeatureKey.NAT,
        FeatureKey.PBR,
        FeatureKey.IPSEC_VPN,
    },
    DeviceDomain.FIREWALL: {
        FeatureKey.ZONE,
        FeatureKey.ADDRESS_OBJECT,
        FeatureKey.SERVICE_OBJECT,
        FeatureKey.SECURITY_POLICY,
    },
}

MANUAL_REVIEW_UNKNOWN = "unknown_capability"
MANUAL_REVIEW_NO_CHECKER = "unverifiable_checker_missing"
MANUAL_REVIEW_PARTIAL_SRC = "source_partial"
MANUAL_REVIEW_PARTIAL_TGT = "target_partial"

# Capability classification → issue category/severity mapping matrix.
# Each entry defines how a capability status translates to validation output.
# Used by CompositeValidator._adjust_coverage_against_baseline and other
# capability-aware issue generation.
CLASSIFICATION_TO_ISSUE_PARAMS: dict[str, tuple[str, str]] = {
    # unknown → HIGH manual_review (cannot assess risk)
    MANUAL_REVIEW_UNKNOWN: ("manual_review", "high"),
    # checker missing → MEDIUM manual_review (need human eyes)
    MANUAL_REVIEW_NO_CHECKER: ("manual_review", "medium"),
    # source side partial → MEDIUM manual_review (may miss features)
    MANUAL_REVIEW_PARTIAL_SRC: ("manual_review", "medium"),
    # target side partial → MEDIUM manual_review (may downgrade)
    MANUAL_REVIEW_PARTIAL_TGT: ("manual_review", "medium"),
}


def get_classification_issue_params(class_name: str) -> tuple[str, str]:
    """Return (category_literal, severity_literal) for a capability
    classification reason string.

    The returned strings match ValidationCategory.value and IRRiskLevel.value
    for direct construction.
    """
    return CLASSIFICATION_TO_ISSUE_PARAMS.get(
        class_name, ("manual_review", "medium"),
    )


@dataclass
class CapabilityBaseline:
    auto_verifiable_semantics: set[FeatureKey] = field(default_factory=set)
    manual_review_semantics: dict[str, list[FeatureKey]] = field(default_factory=dict)
    unsupported_semantics: set[FeatureKey] = field(default_factory=set)
    total_features_considered: int = 0

    def __post_init__(self):
        if not self.manual_review_semantics:
            self.manual_review_semantics = {}

    @staticmethod
    def derive(
        src_capabilities: dict[FeatureKey, FeatureSupport],
        tgt_capabilities: dict[FeatureKey, FeatureSupport],
        src_domain: DeviceDomain | None = None,
        tgt_domain: DeviceDomain | None = None,
    ) -> CapabilityBaseline:
        auto_set: set[FeatureKey] = set()
        manual: dict[str, list[FeatureKey]] = {}
        unsupported_set: set[FeatureKey] = set()
        registry = _registry_for_domains(src_domain, tgt_domain)

        all_keys: set[FeatureKey] = set(src_capabilities.keys())
        # also include keys present in tgt if they have non-None support for src-relevant features
        # but only if src has a non-unsupported status for them
        for key in tgt_capabilities:
            src_sup = src_capabilities.get(key)
            if src_sup is None:
                continue
            all_keys.add(key)

        for key in sorted(all_keys, key=lambda k: k.value):
            src_sup = src_capabilities.get(key)
            if src_sup is None:
                continue

            src_st = src_sup.status
            tgt_sup = tgt_capabilities.get(key)

            if src_st == FeatureSupportStatus.UNSUPPORTED:
                continue

            if src_st == FeatureSupportStatus.UNKNOWN:
                _add_manual(manual, key, MANUAL_REVIEW_UNKNOWN)
                continue

            if tgt_sup is None or tgt_sup.status == FeatureSupportStatus.UNSUPPORTED:
                unsupported_set.add(key)
                continue

            tgt_st = tgt_sup.status

            if tgt_st == FeatureSupportStatus.UNKNOWN:
                _add_manual(manual, key, MANUAL_REVIEW_UNKNOWN)
                continue

            if src_st == FeatureSupportStatus.PARTIAL:
                _add_manual(manual, key, MANUAL_REVIEW_PARTIAL_SRC)
                continue

            if src_st == FeatureSupportStatus.FULL:
                if tgt_st == FeatureSupportStatus.PARTIAL:
                    _add_manual(manual, key, MANUAL_REVIEW_PARTIAL_TGT)
                    continue

                if tgt_st == FeatureSupportStatus.FULL:
                    if key in registry:
                        auto_set.add(key)
                    else:
                        _add_manual(manual, key, MANUAL_REVIEW_NO_CHECKER)
                    continue

        baseline = CapabilityBaseline(
            auto_verifiable_semantics=auto_set,
            unsupported_semantics=unsupported_set,
            total_features_considered=len(auto_set)
                + _count_manual(manual)
                + len(unsupported_set),
        )
        baseline.manual_review_semantics = manual
        return baseline

    def to_dict(self) -> dict[str, Any]:
        return {
            "auto_verifiable_semantics": sorted(
                k.value for k in self.auto_verifiable_semantics
            ),
            "manual_review_semantics": {
                reason: sorted(k.value for k in keys)
                for reason, keys in sorted(self.manual_review_semantics.items())
            },
            "unsupported_semantics": sorted(
                k.value for k in self.unsupported_semantics
            ),
            "total_features_considered": self.total_features_considered,
        }

    @property
    def auto_verifiable_count(self) -> int:
        return len(self.auto_verifiable_semantics)

    @property
    def manual_review_count(self) -> int:
        return _count_manual(self.manual_review_semantics)

    @property
    def unsupported_count(self) -> int:
        return len(self.unsupported_semantics)

    @property
    def verifiability_rate(self) -> float:
        if self.total_features_considered == 0:
            return 1.0
        return self.auto_verifiable_count / self.total_features_considered


def _registry_for_domains(
    src_domain: DeviceDomain | None,
    tgt_domain: DeviceDomain | None,
) -> set[FeatureKey]:
    result: set[FeatureKey] = set()
    for d in (src_domain, tgt_domain):
        if d and d in VERIFIABLE_FEATURE_REGISTRY:
            result.update(VERIFIABLE_FEATURE_REGISTRY[d])
    return result


def _add_manual(
    manual: dict[str, list[FeatureKey]],
    key: FeatureKey,
    reason: str,
) -> None:
    manual.setdefault(reason, []).append(key)


def _count_manual(manual: dict[str, list[FeatureKey]]) -> int:
    return sum(len(v) for v in manual.values())
