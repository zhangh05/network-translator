from __future__ import annotations
import importlib
import logging
from pathlib import Path
from typing import Dict, List, Optional

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer
from core.analyzers.noop import NoopAnalyzer

logger = logging.getLogger("translator.analyzers")


def _load_known_analyzers() -> Dict[str, str]:
    registry_path = Path(__file__).resolve().parent.parent.parent / "knowledge_data" / "features" / "registry.yaml"
    if not registry_path.exists():
        return {}
    try:
        import yaml
        with open(registry_path) as f:
            data = yaml.safe_load(f) or {}
        features = data.get("features", {})
        return {
            name: meta["analyzer"]
            for name, meta in features.items()
            if isinstance(meta, dict) and "analyzer" in meta
        }
    except Exception as exc:
        logger.warning("Failed to load analyzer mappings from registry: %s", exc)
        return {}


class AnalyzerRegistry:
    def __init__(self):
        self._analyzers: Dict[str, FeatureAnalyzer] = {}
        self._load_from_registry()

    def _load_from_registry(self):
        known = _load_known_analyzers()
        for feature, analyzer_key in known.items():
            try:
                module_path = f"core.analyzers.{analyzer_key}"
                mod = importlib.import_module(module_path)
                class_name = "".join(p.capitalize() for p in analyzer_key.split("_")) + "Analyzer"
                cls = getattr(mod, class_name, None)
                if cls is not None and issubclass(cls, FeatureAnalyzer) and cls is not FeatureAnalyzer:
                    self._analyzers[feature] = cls()
                    logger.debug("Registered analyzer %s for feature '%s'", analyzer_key, feature)
                    continue
                logger.debug("Analyzer class %s not found in %s for feature '%s', will no-op", class_name, module_path, feature)
            except Exception as exc:
                logger.debug("Failed to load analyzer for feature '%s': %s", feature, exc)

    def get_analyzer(self, feature: str) -> FeatureAnalyzer:
        return self._analyzers.get(feature, NoopAnalyzer(feature))

    def has_analyzer(self, feature: str) -> bool:
        return feature in self._analyzers

    def get_registered_features(self) -> List[str]:
        return list(self._analyzers.keys())

    def analyze(self, feature: str, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        analyzer = self.get_analyzer(feature)
        return analyzer.analyze(config_text, vendor, domain, platform)

    def analyze_all(self, config_text: str, vendor: str, domain: str, platform: str, features: List[str]) -> List[FeatureAnalysis]:
        results = []
        seen = set()
        for feat in features:
            if feat in seen:
                continue
            seen.add(feat)
            try:
                result = self.analyze(feat, config_text, vendor, domain, platform)
                results.append(result)
            except Exception as exc:
                results.append(FeatureAnalysis(
                    feature=feat,
                    status="error",
                    risk_level="warning",
                    notes=[f"Analyzer error: {exc}"],
                ))
        return results
