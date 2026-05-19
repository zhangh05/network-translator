from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer


class NoopAnalyzer(FeatureAnalyzer):
    def __init__(self, feature: str = ""):
        self._feature = feature

    @property
    def feature_name(self) -> str:
        return self._feature

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        return FeatureAnalysis(
            feature=self._feature,
            status="skipped",
            risk_level="info",
            notes=[f"No analyzer registered for '{self._feature}'"],
        )
