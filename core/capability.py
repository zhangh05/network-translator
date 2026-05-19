# core/capability.py
"""CapabilityMap — per-feature vendor support status query."""

from __future__ import annotations
import os
from pathlib import Path
from typing import Dict, Optional

try:
    import yaml
except ImportError:
    yaml = None  # fallback: require PyYAML for capability map


_CAPABILITY_FILE = Path(__file__).parent.parent / "knowledge_data" / "capability_map.yaml"
_cache: Optional[Dict] = None


def _load_map() -> dict:
    global _cache
    if _cache is not None:
        return _cache
    if yaml is None:
        _cache = {}
        return _cache
    try:
        with open(_CAPABILITY_FILE, "r") as f:
            _cache = yaml.safe_load(f) or {}
    except Exception:
        _cache = {}
    return _cache


def get_feature_status(feature: str, vendor: str) -> str:
    """查询某 feature 在指定 vendor 的支持状态。
    返回: supported | partial | unsupported | unknown
    """
    m = _load_map()
    entry = m.get(feature)
    if not entry:
        return "unknown"
    status = entry.get(vendor, "unknown")
    if status not in ("supported", "partial", "unsupported"):
        return "unknown"
    return status


def get_feature_status_for_translation(source_feature: str, source_vendor: str, target_vendor: str) -> str:
    """查询从 source_vendor 到 target_vendor 翻译时某 feature 的状态。
    优先检查目标厂商支持，再检查 source->target 映射。
    """
    return get_feature_status(source_feature, target_vendor)


def severity_for_status(status: str) -> str:
    if status == "unsupported":
        return "fatal"
    if status == "partial":
        return "warning"
    if status == "unknown":
        return "warning"
    return "info"
