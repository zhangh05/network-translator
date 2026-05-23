from __future__ import annotations

from core.domain.base import DeviceDomain, DomainProfile, FeatureKey
from core.domain.detector import DomainDetector, DomainDetectionResult

# Legacy graph compatibility — ParseNode and other graph nodes import
# detect_domain / detect_platform from this package. New code should use
# DomainDetector from core.domain.detector instead.
from core.domain_legacy import detect_domain, detect_platform

__all__ = [
    # New architecture
    "DeviceDomain", "DomainProfile", "FeatureKey",
    "DomainDetector", "DomainDetectionResult",
    # Legacy graph compatibility (do not use in new code)
    "detect_domain", "detect_platform",
]
