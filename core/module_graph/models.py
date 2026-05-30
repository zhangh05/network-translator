from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class ConfigModule:
    """Auditable source-config unit used before semantic translation."""

    module_id: str
    feature: str
    vendor: str
    start_line: int
    end_line: int
    source_lines: list[str]
    provides: list[str] = field(default_factory=list)
    consumes: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    status: str = "translatable"
    manual_review_reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ModuleDependency:
    """Dependency edge from a consumer module to a provider module."""

    from_module: str
    to_module: str
    label: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ModuleGraph:
    """Config modules plus cross-module references."""

    modules: list[ConfigModule] = field(default_factory=list)
    edges: list[ModuleDependency] = field(default_factory=list)

    def by_feature(self, feature: str) -> list[ConfigModule]:
        return [module for module in self.modules if module.feature == feature]

    def manual_review_modules(self) -> list[ConfigModule]:
        return [module for module in self.modules if module.status == "manual_review"]

    def to_dict(self) -> dict:
        return {
            "modules": [module.to_dict() for module in self.modules],
            "edges": [edge.to_dict() for edge in self.edges],
        }
