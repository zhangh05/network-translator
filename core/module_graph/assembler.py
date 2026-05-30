from __future__ import annotations

from dataclasses import asdict, dataclass

from core.module_graph.builder import ordered_modules
from core.module_graph.models import ConfigModule, ModuleGraph


@dataclass(frozen=True)
class ModuleSection:
    module_id: str
    feature: str
    status: str
    start_line: int
    end_line: int
    text: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class AssemblyResult:
    sections: list[ModuleSection]
    text: str

    def to_dict(self) -> dict:
        return {
            "sections": [section.to_dict() for section in self.sections],
            "text": self.text,
        }


def assemble_source_modules(graph: ModuleGraph) -> AssemblyResult:
    """Render source modules in dependency-aware order.

    This is a deterministic assembly primitive for audit and future
    module-by-module translation. It intentionally preserves source text instead
    of claiming target-vendor equivalence.
    """

    sections: list[ModuleSection] = []
    chunks: list[str] = []
    for module in ordered_modules(graph):
        header = _module_header(module)
        body = "\n".join(module.source_lines)
        text = f"{header}\n{body}".rstrip()
        sections.append(
            ModuleSection(
                module_id=module.module_id,
                feature=module.feature,
                status=module.status,
                start_line=module.start_line,
                end_line=module.end_line,
                text=text,
            )
        )
        chunks.append(text)
    return AssemblyResult(sections=sections, text="\n\n".join(chunks))


def _module_header(module: ConfigModule) -> str:
    parts = [
        f"### module {module.module_id}",
        f"feature={module.feature}",
        f"status={module.status}",
        f"lines={module.start_line}-{module.end_line}",
    ]
    if module.depends_on:
        parts.append("depends_on=" + ",".join(module.depends_on))
    if module.provides:
        parts.append("provides=" + ",".join(module.provides))
    if module.consumes:
        parts.append("consumes=" + ",".join(module.consumes))
    if module.tags:
        parts.append("tags=" + ",".join(module.tags))
    return " | ".join(parts)
