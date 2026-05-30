from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from core.module_graph.builder import ordered_modules
from core.module_graph.models import ConfigModule, ModuleGraph
from core.rule_translator import RuleBasedTranslator


@dataclass(frozen=True)
class ModuleTranslationResult:
    module_id: str
    feature: str
    status: str
    source_lines: list[str]
    translated_lines: list[str] = field(default_factory=list)
    manual_review_lines: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)
    consumes: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ModuleTranslationAssembly:
    results: list[ModuleTranslationResult]
    deployable_config: str
    manual_review_config: str

    def to_dict(self) -> dict:
        return {
            "results": [result.to_dict() for result in self.results],
            "deployable_config": self.deployable_config,
            "manual_review_config": self.manual_review_config,
        }


def translate_module_graph(graph: ModuleGraph, from_vendor: str, to_vendor: str) -> ModuleTranslationAssembly:
    """Translate modules independently and assemble deterministic output.

    This is the first replacement layer for flat fallback translation. It keeps
    uncertain lines out of deployable config and records them as review evidence.
    """

    translator = RuleBasedTranslator()
    results: list[ModuleTranslationResult] = []
    deployable_chunks: list[str] = []
    review_chunks: list[str] = []

    for module in ordered_modules(graph):
        result = _translate_module(module, from_vendor, to_vendor, translator)
        results.append(result)
        if result.translated_lines:
            deployable_chunks.extend(result.translated_lines)
        if result.manual_review_lines:
            review_chunks.extend(result.manual_review_lines)

    return ModuleTranslationAssembly(
        results=results,
        deployable_config="\n".join(_dedupe_adjacent_blank_lines(deployable_chunks)).strip(),
        manual_review_config="\n".join(_dedupe_adjacent_blank_lines(review_chunks)).strip(),
    )


def _translate_module(
    module: ConfigModule,
    from_vendor: str,
    to_vendor: str,
    translator: RuleBasedTranslator,
) -> ModuleTranslationResult:
    source_text = "\n".join(module.source_lines)
    if module.status == "manual_review":
        return ModuleTranslationResult(
            module_id=module.module_id,
            feature=module.feature,
            status="manual_review",
            source_lines=module.source_lines,
            manual_review_lines=_source_review_lines(module),
            provides=module.provides,
            consumes=module.consumes,
            depends_on=module.depends_on,
            reason=module.manual_review_reason,
        )

    if module.feature == "acl_binding":
        return _translate_acl_binding_module(module, from_vendor, to_vendor, translator)

    translated = translator.translate(source_text, from_vendor, to_vendor)
    body = _extract_config_block(translated).strip()
    translated_lines: list[str] = []
    review_lines: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "MANUAL_REVIEW" in stripped:
            review_lines.append(line)
        else:
            translated_lines.append(line)

    status = "translated" if translated_lines else "manual_review"
    reason = "" if translated_lines else "该模块没有生成确定的可部署配置"
    if review_lines and translated_lines:
        status = "partial"
        reason = "模块部分命令需要人工复核"

    return ModuleTranslationResult(
        module_id=module.module_id,
        feature=module.feature,
        status=status,
        source_lines=module.source_lines,
        translated_lines=translated_lines,
        manual_review_lines=review_lines or ([] if translated_lines else _source_review_lines(module, reason)),
        provides=module.provides,
        consumes=module.consumes,
        depends_on=module.depends_on,
        reason=reason,
    )


def _translate_acl_binding_module(
    module: ConfigModule,
    from_vendor: str,
    to_vendor: str,
    translator: RuleBasedTranslator,
) -> ModuleTranslationResult:
    interface_name = _first_resource_value(module.consumes, "interface:")
    source_text = "\n".join(module.source_lines)
    if interface_name:
        source_text = f"interface {interface_name}\n " + "\n ".join(module.source_lines)

    translated = translator.translate(source_text, from_vendor, to_vendor)
    body = _extract_config_block(translated).strip()
    translated_lines: list[str] = []
    review_lines: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "MANUAL_REVIEW" in stripped:
            review_lines.append(line)
        else:
            translated_lines.append(line)

    status = "translated" if translated_lines else "manual_review"
    reason = "" if translated_lines else "ACL 绑定没有生成确定的可部署配置"
    return ModuleTranslationResult(
        module_id=module.module_id,
        feature=module.feature,
        status=status,
        source_lines=module.source_lines,
        translated_lines=translated_lines,
        manual_review_lines=review_lines or ([] if translated_lines else _source_review_lines(module, reason)),
        provides=module.provides,
        consumes=module.consumes,
        depends_on=module.depends_on,
        reason=reason,
    )


def _first_resource_value(resources: list[str], prefix: str) -> str:
    for resource in resources:
        if resource.startswith(prefix):
            return resource[len(prefix):]
    return ""


def _source_review_lines(module: ConfigModule, reason: str = "") -> list[str]:
    reason_text = reason or module.manual_review_reason or "需要人工复核"
    lines = [f"# MODULE_REVIEW {module.module_id} {module.feature}: {reason_text}"]
    lines.extend(f"# SOURCE line {module.start_line + idx}: {line}" for idx, line in enumerate(module.source_lines))
    return lines


def _dedupe_adjacent_blank_lines(lines: list[str]) -> list[str]:
    output: list[str] = []
    previous_blank = False
    for line in lines:
        is_blank = not line.strip()
        if is_blank and previous_blank:
            continue
        output.append(line)
        previous_blank = is_blank
    return output


def _extract_config_block(text: str) -> str:
    match = re.search(r"```[a-zA-Z0-9_-]*\n(.*?)```", text or "", re.DOTALL)
    if match:
        return match.group(1).strip()
    return text or ""
