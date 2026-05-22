from __future__ import annotations
from core.vendor.base import (
    VendorPlatformProfile, InterfaceNaming, VendorSignature,
    ForbiddenPattern, FeatureSupport, FeatureSupportStatus,
    VendorLimitation,
)
from core.vendor.enums import FeatureKey, FeatureSupportStatus, ForbiddenPatternCategory

_profiles: dict[str, VendorPlatformProfile] = {}


def register_profile(profile: VendorPlatformProfile) -> None:
    _profiles[profile.key] = profile


def get_profile(key: str) -> VendorPlatformProfile | None:
    return _profiles.get(key)


def list_profiles() -> list[VendorPlatformProfile]:
    return list(_profiles.values())


def init_profiles() -> dict[str, VendorPlatformProfile]:
    import core.vendor.profile_cisco_ios_xe
    import core.vendor.profile_h3c_comware
    import core.vendor.profile_huawei_vrp
    import core.vendor.profile_huawei_usg
    import core.vendor.profile_ruijie_rgos
    import core.vendor.profile_hillstone_stoneos
    import core.vendor.profile_topsec_tos
    import core.vendor.profile_dptech_fw
    return _profiles


__all__ = [
    "VendorPlatformProfile", "InterfaceNaming", "VendorSignature",
    "ForbiddenPattern", "FeatureSupport", "FeatureSupportStatus",
    "VendorLimitation", "FeatureKey",
    "register_profile", "get_profile", "list_profiles", "init_profiles",
]
