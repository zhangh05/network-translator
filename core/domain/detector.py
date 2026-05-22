from __future__ import annotations
import re
from dataclasses import dataclass, field
from core.domain.base import DeviceDomain, FeatureKey


@dataclass
class DomainDetectionResult:
    primary_domain: DeviceDomain
    confidence: float
    evidence: dict[str, float]
    detected_features: list[FeatureKey]
    secondary_features: list[FeatureKey] = field(default_factory=list)


class DomainDetector:
    """Rule-based domain detector using signature pattern scoring.

    Strategy:
    - Each domain has weighted signature patterns (regex, weight)
    - Matches are scored per domain; highest score + threshold check = primary
    - L3 switch heuristic: strong switching signal + routing signals = SWITCH
      primary with routing features demoted to secondary_features
    """

    # Signature format: (regex_pattern, weight, feature_key_if_matched)
    SWITCH_SIG = [
        (r'switchport', 3.0, FeatureKey.TRUNK),
        (r'vlan batch', 3.0, FeatureKey.VLAN),
        (r'port trunk', 2.0, FeatureKey.TRUNK),
        (r'port access', 2.0, FeatureKey.VLAN),
        (r'spanning-tree', 3.0, FeatureKey.STP),
        (r'stp mode', 2.0, FeatureKey.STP),
        (r'interface Vlan-?interface', 3.0, FeatureKey.SVI),
        (r'lacp', 1.5, FeatureKey.LACP),
        (r'lldp', 1.0, FeatureKey.LLDP),
    ]
    ROUTER_SIG = [
        (r'router ospf', 4.0, FeatureKey.OSPF),
        (r'router bgp', 4.0, FeatureKey.BGP),
        (r'ip route ', 2.0, FeatureKey.STATIC_ROUTE),
        (r'vrf definition', 3.0, FeatureKey.VRF),
        (r'route-map', 2.0, FeatureKey.PBR),
        (r'neighbor \d+\.\d+\.\d+\.\d+', 3.0, FeatureKey.BGP),
        (r'ip prefix-list', 2.0, FeatureKey.ACL),
        (r'ip nat ', 2.0, FeatureKey.NAT),
    ]
    FIREWALL_SIG = [
        (r'security-zone', 4.0, FeatureKey.ZONE),
        (r'zone-pair security', 4.0, FeatureKey.ZONE),
        (r'policy interzone', 3.0, FeatureKey.SECURITY_POLICY),
        (r'security-policy', 3.0, FeatureKey.SECURITY_POLICY),
        (r'nat server', 2.0, FeatureKey.NAT_POLICY),
        (r'address-group', 2.0, FeatureKey.ADDRESS_OBJECT),
        (r'service-group', 2.0, FeatureKey.SERVICE_OBJECT),
        (r'user-?auth', 1.0, FeatureKey.USER_AUTH),
    ]

    SWITCH_THRESHOLD = 4.0  # minimum switch score to trigger L3 switch heuristic

    def __init__(self):
        self.signatures = {
            DeviceDomain.SWITCH: self.SWITCH_SIG,
            DeviceDomain.ROUTER: self.ROUTER_SIG,
            DeviceDomain.FIREWALL: self.FIREWALL_SIG,
        }

    def detect(
        self, config_text: str, vendor_hint: str | None = None
    ) -> DomainDetectionResult:
        scores: dict[DeviceDomain, float] = {}
        all_features: dict[DeviceDomain, list[FeatureKey]] = {
            DeviceDomain.SWITCH: [],
            DeviceDomain.ROUTER: [],
            DeviceDomain.FIREWALL: [],
        }

        for domain, sigs in self.signatures.items():
            total = 0.0
            features: list[FeatureKey] = []
            for pattern, weight, fk in sigs:
                if re.search(pattern, config_text, re.IGNORECASE | re.MULTILINE):
                    total += weight
                    features.append(fk)
            if total > 0:
                scores[domain] = total
                all_features[domain] = features

        evidence = {d.value: round(s, 4) for d, s in scores.items()}

        if scores:
            primary = max(scores, key=scores.get)
            primary_score = scores[primary]

            # L3 switch heuristic: if SWITCH score >= threshold AND signals
            # from other domains exist, keep SWITCH as primary
            switch_score = scores.get(DeviceDomain.SWITCH, 0.0)
            if (
                primary != DeviceDomain.SWITCH
                and switch_score >= self.SWITCH_THRESHOLD
            ):
                primary = DeviceDomain.SWITCH
                primary_score = switch_score

            total_all = sum(scores.values())
            confidence = round(primary_score / total_all, 4) if total_all > 0 else 0.0

            detected_features = all_features[primary]
            secondary_features = []
            for domain, feats in all_features.items():
                if domain != primary:
                    secondary_features.extend(feats)
        else:
            primary = DeviceDomain.SWITCH
            confidence = 0.0
            detected_features = []
            secondary_features = []

        return DomainDetectionResult(
            primary_domain=primary,
            confidence=confidence,
            evidence=evidence,
            detected_features=detected_features,
            secondary_features=secondary_features,
        )
