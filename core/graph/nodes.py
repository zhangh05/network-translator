# -*- coding: utf-8 -*-
"""Translation graph node implementations."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from core import get_llm, LLM
from core.graph import Node, NodeResult, NodeStatus, State
from core.ir import translate_config
from core.risk_decision import (
    RiskSignal, RiskSeverity, RiskSource, RiskDecision,
    decide_deployability, HIGH_RISK_FEATURES,
)
from core.rule_translator import RuleBasedTranslator
from core.semantic_compare import SemanticComparator, IRBlock
from memory import EpisodicMemory, TranslationEvent
from tools import ConfigDiffer, ConfigParser, ConfigValidator, KnowledgeRetriever, ValidationResult

logger = logging.getLogger("translator.nodes")


def extract_config_block(text: str) -> str:
    match = re.search(r"```[\w-]*\n(.+?)```", text or "", re.DOTALL)
    return match.group(1) if match else (text or "")


def _normalize_analyzer_results(state: State) -> dict:
    """Normalize analyzer_results (list[dict] or dict) to dict keyed by feature."""
    raw = state.get("analyzer_results", {})
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, list):
        normalized = {}
        for item in raw:
            if isinstance(item, dict):
                key = item.get("feature", str(id(item)))
                normalized[key] = item
        return normalized
    return {}


class ParseNode(Node):
    def __init__(self, node_id: str = "parse"):
        super().__init__(node_id, "parse")
        self.parser = ConfigParser()

    def execute(self, state: State) -> NodeResult:
        config_text = state.get("config_text")
        requested_vendor = state.get("from_vendor")
        vendor_hint = state.get("vendor_hint") or (requested_vendor if requested_vendor != "auto" else None)
        if not config_text:
            return NodeResult(self.node_id, NodeStatus.FAILED, error="missing config_text")

        parsed = self.parser.parse(config_text, vendor_hint)
        vendor = vendor_hint or parsed.vendor or "unknown"
        state.set("parsed_config", parsed)
        state.set("from_vendor", vendor)

        # ── Domain / platform / feature detection ────────────────────
        from core.domain import detect_domain, detect_platform

        source_domain = state.get("source_domain", "auto")
        if source_domain in (None, "", "auto"):
            source_domain = detect_domain(vendor, config_text)
            state.set("source_domain", source_domain)

        source_platform = state.get("source_platform", "auto")
        if source_platform in (None, "", "auto"):
            source_platform = detect_platform(vendor, source_domain, config_text)
            state.set("source_platform", source_platform)

        # Target domain defaults to source domain if not set
        target_domain = state.get("target_domain", "")
        if not target_domain or target_domain == "auto":
            target_domain = source_domain
            state.set("target_domain", target_domain)

        target_platform = state.get("target_platform", "")
        if not target_platform or target_platform == "auto":
            target_platform = ""
            state.set("target_platform", target_platform)

        # Feature detection
        try:
            from tools.knowledge_manager import detect_features_from_config
            features = detect_features_from_config(config_text)
            state.set("features", features)
        except Exception:
            state.set("features", [])

        try:
            from core.module_graph import build_module_graph
            module_graph = build_module_graph(config_text, vendor=vendor)
            module_summary: dict[str, int] = {}
            for module in module_graph.modules:
                module_summary[module.feature] = module_summary.get(module.feature, 0) + 1
            state.set("module_graph", module_graph.to_dict())
            state.set("module_summary", dict(sorted(module_summary.items())))
        except Exception:
            logger.debug("module graph build skipped", exc_info=True)

        return NodeResult(
            self.node_id,
            NodeStatus.SUCCESS,
            output={
                "vendor": vendor,
                "source_domain": source_domain,
                "source_platform": source_platform,
                "target_domain": target_domain,
                "features": len(state.get("features", [])),
                "hostname": parsed.hostname,
                "interfaces": len(parsed.interfaces),
                "vlans": len(parsed.vlans),
                "acl_count": len(parsed.acl_configs),
            },
            metadata={"raw_lines": len(parsed.raw_lines) if parsed.raw_lines else 0},
        )


class FeatureAnalyzerNode(Node):
    def __init__(self, node_id: str = "feature_analyzer"):
        super().__init__(node_id, "feature_analyzer")

    def execute(self, state: State) -> NodeResult:
        from core.analyzers import AnalyzerRegistry
        registry = AnalyzerRegistry()
        features = state.get("features", [])
        config_text = state.get("config_text", "")
        vendor = state.get("from_vendor", "unknown")
        domain = state.get("source_domain", "")
        platform = state.get("source_platform", "")
        results = registry.analyze_all(config_text, vendor, domain, platform, features)
        state.set("analyzer_results", [r.to_dict() for r in results])
        return NodeResult(
            self.node_id,
            NodeStatus.SUCCESS,
            output={"analyzed": len(results), "registered": len(registry.get_registered_features())},
        )


class KnowledgeNode(Node):
    def __init__(self, node_id: str = "knowledge", knowledge_dir: str = "knowledge_data"):
        super().__init__(node_id, "knowledge")
        self.knowledge = KnowledgeRetriever(knowledge_dir)

    def execute(self, state: State) -> NodeResult:
        from_vendor = state.get("from_vendor", "unknown")
        to_vendor = state.get("to_vendor", "unknown")
        knowledge_context = self.knowledge.get_all_mapping_info(from_vendor, to_vendor)
        interface_types = self.knowledge.get_interface_mapping(from_vendor, to_vendor)
        state.set("interface_types", json.dumps(interface_types) if interface_types else "")

        try:
            from tools.knowledge_manager import detect_features_from_config
            from core.capability import get_feature_status_for_translation
            config_text = state.get("config_text", "")
            features = detect_features_from_config(config_text)
            cap_notes = []
            for feat in features:
                status = get_feature_status_for_translation(feat, from_vendor, to_vendor)
                if status in ("unsupported", "unknown"):
                    cap_notes.append(f"- {feat}: {status} on {to_vendor}")
            if cap_notes:
                cap_section = "\n\n【能力约束】\n以下功能在目标厂商支持状态受限:"
                cap_section += "\n" + "\n".join(cap_notes)
                cap_section += "\n\n翻译规则："
                cap_section += "\n- unsupported 功能 → translated_lines 留空，notes 说明原因"
                cap_section += "\n- unknown 功能 → 尽量翻译，每行追加 `// MANUAL_REVIEW` 注释"
                knowledge_context += cap_section
                state.set("_capability_features", [f for f in features])
        except Exception:
            logger.debug("capability check skipped", exc_info=True)

        state.set("knowledge_context", knowledge_context)
        return NodeResult(
            self.node_id,
            NodeStatus.SUCCESS,
            output={"knowledge_lines": len(knowledge_context.splitlines())},
        )


_PROMPT_VERSION = "4"
_TRANSLATOR_VERSION = "1"  # bump when rule translator changes
_NORMALIZER_VERSION = "1"  # bump when config normalizer changes
_CACHE_DIR = "cache_data"


class CacheNode(Node):
    def __init__(self, node_id: str = "cache", cache_dir: str = _CACHE_DIR):
        super().__init__(node_id, "cache")
        self.cache_dir = cache_dir

    def _knowledge_hash(self, to_vendor: str) -> str:
        from tools.knowledge_manager import KNOWLEDGE_DIR, VENDOR_DIR
        vendor_dir_name = VENDOR_DIR.get(to_vendor.lower(), "huawei")
        base = KNOWLEDGE_DIR / vendor_dir_name
        h = hashlib.sha256()
        if base.exists():
            for f in sorted(base.iterdir()):
                if f.suffix == ".md":
                    try:
                        h.update(f.read_bytes())
                    except Exception:
                        pass
        # Also hash feature registry
        registry = KNOWLEDGE_DIR / "features" / "registry.yaml"
        if registry.exists():
            try:
                h.update(registry.read_bytes())
            except Exception:
                pass
        # Also hash capability map
        cap_map = KNOWLEDGE_DIR / "capability_map.yaml"
        if cap_map.exists():
            try:
                h.update(cap_map.read_bytes())
            except Exception:
                pass
        # Also hash domain profiles and domain knowledge files
        domains_dir = KNOWLEDGE_DIR / "domains"
        if domains_dir.exists():
            for domain_dir in sorted(domains_dir.iterdir()):
                if not domain_dir.is_dir():
                    continue
                vdir = domain_dir / vendor_dir_name
                if not vdir.exists():
                    continue
                for f in sorted(vdir.iterdir()):
                    if f.suffix in (".md", ".yaml", ".yml"):
                        try:
                            h.update(f.read_bytes())
                        except Exception:
                            pass
        return h.hexdigest()[:12]

    def _cache_path(self, key: str) -> str:
        return os.path.join(self.cache_dir, f"{key}.json")

    def _build_key(self, config_text: str, from_vendor: str, to_vendor: str,
                   llm_model: str,
                   source_domain: str = "", source_platform: str = "",
                   target_domain: str = "", target_platform: str = "",
                   features: list = None) -> str:
        kh = self._knowledge_hash(to_vendor)
        feat_str = ",".join(sorted(features)) if features else ""
        parts = "||".join([
            config_text, from_vendor, to_vendor,
            source_domain, source_platform,
            target_domain, target_platform,
            feat_str,
            kh, _PROMPT_VERSION, _TRANSLATOR_VERSION, _NORMALIZER_VERSION,
            llm_model or "default",
        ])
        return hashlib.sha256(parts.encode()).hexdigest()

    def execute(self, state: State) -> NodeResult:
        config_text = state.get("config_text", "")
        from_vendor = state.get("from_vendor", "unknown")
        to_vendor = state.get("to_vendor", "unknown")
        llm = None
        try:
            llm = get_llm()
            llm_model = llm.model if hasattr(llm, "model") else ""
        except Exception:
            llm_model = ""

        source_domain = state.get("source_domain", "")
        source_platform = state.get("source_platform", "")
        target_domain = state.get("target_domain", "")
        target_platform = state.get("target_platform", "")
        features = state.get("features")

        key = self._build_key(config_text, from_vendor, to_vendor, llm_model,
                               source_domain, source_platform,
                               target_domain, target_platform,
                               features)
        state.set("_cache_key", key)
        path = self._cache_path(key)

        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    cached = json.load(f)
                state.set("translated_config", cached.get("translated_config", ""))
                state.set("ir_translation", cached.get("ir_translation", []))
                ir_source_raw = cached.get("ir_source", [])
                ir_source_objs = []
                for b in ir_source_raw:
                    if isinstance(b, dict):
                        kwargs = {k: v for k, v in b.items() if k in ("type", "function", "params", "original_lines", "confidence")}
                        kwargs.setdefault("params", {})
                        ir_source_objs.append(IRBlock(**kwargs))
                    else:
                        ir_source_objs.append(b)
                state.set("ir_source", ir_source_objs)
                state.set("ir_compare", cached.get("ir_compare", {}))
                state.set("cache_hit", True)
                logger.info("Cache HIT for key=%s", key[:12])
                return NodeResult(
                    self.node_id, NodeStatus.SUCCESS,
                    output={"cached": True, "key": key[:12]},
                    metadata={"cached": True},
                )
            except Exception as exc:
                logger.warning("Cache read failed for key=%s: %s", key[:12], exc)

        state.set("cache_hit", False)
        return NodeResult(
            self.node_id, NodeStatus.SUCCESS,
            output={"cached": False, "key": key[:12]},
        )


class TranslateNode(Node):
    def __init__(
        self,
        node_id: str = "translate",
        llm: Optional[LLM] = None,
        knowledge_dir: str = "knowledge_data",
        agent=None,
    ):
        super().__init__(node_id, "translate")
        self.llm = llm if llm is not None else get_llm()
        self.knowledge = KnowledgeRetriever(knowledge_dir)
        self.agent = agent

    def _build_analyzer_context(self, state: State) -> str:
        analyzer_results = _normalize_analyzer_results(state)
        lines = []
        for feature_key, analysis in analyzer_results.items():
            if not isinstance(analysis, dict):
                continue
            risk = analysis.get("risk_level", "none")
            if risk == "none":
                continue
            summary = analysis.get("summary", "")
            details = analysis.get("details", {})
            missing_refs = details.get("missing_references", [])
            part = f"[analyzer:{feature_key}] risk={risk}"
            if summary:
                part += f" {summary}"
            if missing_refs:
                part += f" missing_refs={','.join(missing_refs[:5])}"
            lines.append(part)
        if not lines:
            return ""
        ctx = "【配置分析器发现的风险项】\n" + "\n".join(lines)
        ctx += "\n注意：以上风险项仅作为参考，请根据实际语义合理翻译缺失引用对象。"
        return ctx

    def execute(self, state: State) -> NodeResult:
        if state.get("cache_hit"):
            return NodeResult(self.node_id, NodeStatus.SUCCESS, output="(from cache)")

        config_text = state.get("config_text")
        from_vendor = state.get("from_vendor", "unknown")
        to_vendor = state.get("to_vendor", "unknown")
        if not config_text:
            return NodeResult(self.node_id, NodeStatus.FAILED, error="missing config_text")

        knowledge_context = state.get("knowledge_context", "")
        if not knowledge_context:
            logger.warning("KnowledgeNode did not populate knowledge_context; falling back to independent retrieval")
            try:
                from tools.knowledge_manager import retrieve_knowledge_by_config
                knowledge_context = retrieve_knowledge_by_config(config_text, to_vendor)
                if len(knowledge_context) > 2500:
                    knowledge_context = knowledge_context[:2500] + "\n\n...(truncated)"
            except Exception:
                logger.warning("Knowledge fallback retrieval failed", exc_info=True)

        analyzer_ctx = self._build_analyzer_context(state)

        translation_result = translate_config(
            config_text, from_vendor, to_vendor, self.llm,
            knowledge_context=knowledge_context or None,
            source_domain=state.get("source_domain", ""),
            source_platform=state.get("source_platform", ""),
            target_domain=state.get("target_domain", ""),
            target_platform=state.get("target_platform", ""),
            features=state.get("features"),
            analyzer_context=analyzer_ctx or None,
            capability_notes=state.get("capability_notes"),
        )

        if isinstance(translation_result, list) and translation_result and "error" in translation_result[0]:
            return NodeResult(self.node_id, NodeStatus.FAILED, error=translation_result[0]["error"])
        if not isinstance(translation_result, list):
            return NodeResult(self.node_id, NodeStatus.FAILED, error="invalid translation result")
        state.set("ir_translation", translation_result)

        translated_lines = []
        for block in translation_result:
            if isinstance(block, dict) and block.get("translated_lines"):
                translated_lines.extend(block["translated_lines"])

        translated_config = "\n".join(translated_lines).strip()
        if translated_config:
            translated_config = f"```{to_vendor}\n{translated_config}\n```"
        state.set("translated_config", translated_config)

        ir_source = [
            IRBlock(
                type=b.get("type", "unknown"),
                function="",
                params={},
                original_lines=b.get("original_lines", []),
                confidence=b.get("confidence", 0.8),
            )
            for b in translation_result
            if isinstance(b, dict)
        ]
        state.set("ir_source", ir_source)

        comparator = SemanticComparator()
        ir_compare = comparator.compare(ir_source, translation_result)
        state.set("ir_compare", ir_compare)

        return NodeResult(
            self.node_id,
            NodeStatus.SUCCESS,
            output=translated_config,
            metadata={
                "from_vendor": from_vendor,
                "to_vendor": to_vendor,
                "translation_blocks_count": len(translation_result),
            },
        )


class ValidateNode(Node):
    def __init__(self, node_id: str = "validate"):
        super().__init__(node_id, "validate")
        self.parser = ConfigParser()
        self.validator = ConfigValidator()

    def _content_quality_checks(self, config_content: str, to_vendor: str, source_config: str = "") -> tuple:
        content_warnings = []
        content_errors = []
        scan_content = self._executable_config_content(config_content)

        if not config_content.strip():
            content_errors.append("翻译结果为空")
            return content_errors, content_warnings

        if re.search(r'<[^>]+>', scan_content):
            content_warnings.append("包含未替换的占位符 <...>，请人工确认")

        placeholder_kws = ['todo', 'placeholder', '请替换', '请修改', '根据实际情况', 'your', 'example.com']
        for kw in placeholder_kws:
            if kw in scan_content.lower():
                content_warnings.append(f"包含待填充标记「{kw}」")
                break

        if '```' in config_content:
            content_errors.append("翻译结果包含嵌套的 Markdown 代码围栏")

        # Source vendor residue detection by target vendor
        residue_patterns = {
            'huawei': [
                (r'\bswitchport\b', 'Cisco switchport 命令'),
                (r'\bstandby\s+\d+', 'Cisco HSRP standby 命令'),
                (r'\baccess-list\b', 'Cisco access-list 命令'),
                (r'\bclass-map\b', 'Cisco class-map'),
                (r'\bpolicy-map\b', 'Cisco policy-map'),
                (r'\bip\s+nat\s+(inside|outside)\b', 'Cisco ip nat inside/outside'),
                (r'\bspanning-tree\b', 'Cisco spanning-tree 命令'),
                (r'\bip\s+dhcp\s+pool\b', 'Cisco dhcp pool 命令'),
                (r'\broute-map\b', 'Cisco route-map 命令'),
                (r'\bip\s+nat\s+inside\s+source\b', 'Cisco ip nat inside source'),
                (r'\bobject-group(?:\s+network|\s+service)\b', 'Cisco object-group'),
                (r'\baccess-group\b', 'Cisco access-group'),
                (r'\bip\s+policy\s+route-map\b', 'Cisco ip policy route-map'),
                (r'\bchannel-group\b', 'Cisco channel-group'),
            ],
            'cisco': [
                (r'\bsysname\b', '华为/H3C sysname 命令'),
                (r'\bvlan\s+batch\b', 'Huawei/H3C vlan batch'),
                (r'\bport\s+link-type\b', 'H3C port link-type'),
                (r'\btraffic\s+classifier\b', 'Huawei traffic classifier'),
                (r'\btraffic\s+behavior\b', 'Huawei traffic behavior'),
                (r'\bip\s+route-static\b', 'Huawei ip route-static'),
                (r'\bundo\b', 'Huawei undo 命令'),
                (r'\binterface\s+GE\b', 'Huawei 简写接口名'),
                (r'\bimport-route\b', 'Huawei/H3C import-route 命令'),
                (r'\bnat\s+outbound\b', 'Huawei/H3C nat outbound'),
                (r'\bsecurity-zone\b', 'Huawei/H3C security-zone'),
                (r'\bsecurity-policy\b', 'Huawei/H3C security-policy'),
                (r'\bacl\s+number\b', 'Huawei/H3C acl number'),
                (r'\brule\s+\d+\s+permit\s+ip\s+source\b', 'Huawei/H3C rule permit ip source 格式'),
                (r'\bip\s+policy-based-route\b', 'Huawei/H3C policy-based-route'),
                (r'\broute-policy\b', 'Huawei/H3C route-policy'),
                (r'\bip-prefix\b', 'Huawei/H3C ip-prefix'),
                (r'\bundo\s+shutdown\b', 'Huawei undo shutdown'),
                (r'\bport\s+link-mode\b', 'H3C port link-mode'),
                (r'\binfo-center\b', 'Huawei/H3C info-center'),
                (r'\blocal-user\b', 'Huawei/H3C local-user'),
                (r'\bstelnet\b', 'Huawei stelnet'),
            ],
            'h3c': [
                (r'\bswitchport\b', 'Cisco switchport 命令'),
                (r'\bstandby\s+\d+', 'Cisco HSRP standby'),
                (r'\bip\s+nat\s+(inside|outside)\b', 'Cisco ip nat inside/outside'),
                (r'\baccess-list\b', 'Cisco access-list'),
                (r'\broute-map\b', 'Cisco route-map 命令'),
                (r'\bip\s+nat\s+inside\s+source\b', 'Cisco ip nat inside source'),
                (r'\bobject-group(?:\s+network|\s+service)\b', 'Cisco object-group'),
                (r'\baccess-group\b', 'Cisco access-group'),
                (r'\binterface\s+Port-channel\b', 'Cisco Port-channel 接口'),
                (r'\bip\s+policy\s+route-map\b', 'Cisco ip policy route-map'),
                (r'\bchannel-group\b', 'Cisco channel-group'),
                (r'\bspanning-tree\b', 'Cisco spanning-tree'),
                (r'\bip\s+dhcp\s+pool\b', 'Cisco dhcp pool'),
            ],
            'asa': [
                (r'\bswitchport\b', 'Cisco IOS switchport'),
                (r'\brouter\s+ospf\b', 'Cisco IOS router ospf'),
                (r'\brouter\s+bgp\b', 'Cisco IOS router bgp'),
                (r'\bip\s+route\s+\S+\s+\S+\s+\S+\b(?!\s*$)', 'Cisco IOS iP route'),
                (r'\baccess-list\s+\d+\b', 'Cisco IOS 编号 access-list'),
                (r'\bip\s+nat\s+(inside|outside)\b', 'Cisco IOS ip nat'),
                (r'\bnat\s+outbound\b', 'Huawei/H3C nat outbound'),
                (r'\bsecurity-zone\b', 'Huawei/H3C security-zone'),
                (r'\bsecurity-policy\b', 'Huawei/H3C security-policy'),
                (r'\broute-policy\b', 'Huawei/H3C route-policy'),
            ],
        }

        patterns = residue_patterns.get(to_vendor.lower(), [])
        for pat, desc in patterns:
            if re.search(pat, scan_content):
                content_warnings.append(f"可能存在源厂商残留：{desc}")

        # BGP redistribute 缺少 AS 号
        bgp_redist = re.findall(r'redistribute\s+bgp', config_content, re.IGNORECASE)
        has_bgp = re.search(r'router\s+bgp\s+\d+', config_content, re.IGNORECASE)
        if bgp_redist and not has_bgp:
            content_warnings.append(
                "redistribute bgp 缺少源 BGP AS 号上下文（router bgp <AS>），目标命令可能需要人工确认"
            )

        # OSPF area dotted decimal 转换校验
        if source_config:
            src_areas = re.findall(r'area\s+(\d+\.\d+\.\d+\.\d+)', source_config, re.IGNORECASE)
            for dotted in src_areas:
                octets = [int(x) for x in dotted.split('.')]
                decimal = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
                if decimal > 0:
                    tgt_areas = re.findall(r'area\s+(\d+(?:\.\d+\.\d+\.\d+)?)', config_content, re.IGNORECASE)
                    found = False
                    for a_str in tgt_areas:
                        if '.' in a_str:
                            parts = [int(x) for x in a_str.split('.')]
                            a_val = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
                        else:
                            a_val = int(a_str)
                        if a_val == decimal or a_val == octets[3]:
                            found = True
                            break
                    if not found:
                        content_warnings.append(
                            f"OSPF area {dotted}（十进制 {decimal}）在翻译结果中未找到匹配 area，可能出现转换错误"
                        )

        return content_errors, content_warnings

    def _generic_validation(self, config_content: str, to_vendor: str) -> tuple:
        parsed = self.parser.parse(config_content, to_vendor)
        result = self.validator.validate(parsed)
        return result, parsed

    def _domain_validation(self, config_content: str, to_vendor: str, source_config: str) -> tuple:
        return self._content_quality_checks(config_content, to_vendor, source_config)

    def _resolve_references(self, config_content: str, target_vendor: str) -> list:
        ref_warnings = []
        tl = target_vendor.lower()

        # route-policy / ip-prefix reference check (Huawei/H3C target)
        if tl in ('huawei', 'h3c'):
            defined_policies = set(re.findall(
                r'^route-policy\s+(\S+)', config_content, re.IGNORECASE | re.MULTILINE
            ))
            defined_prefix_lists = set(re.findall(
                r'^ip\s+ip-prefix\s+(\S+)', config_content, re.IGNORECASE | re.MULTILINE
            ))
            referenced_policies = set(re.findall(
                r'route-policy\s+(\S+)', config_content, re.IGNORECASE
            ))
            referenced_prefix_lists = set(re.findall(
                r'ip-prefix\s+(\S+)', config_content, re.IGNORECASE
            ))
            for rp in referenced_policies:
                if rp not in defined_policies:
                    ref_warnings.append(f"route-policy {rp} 被引用但在输出中未找到定义")
            for pl in referenced_prefix_lists:
                if pl not in defined_prefix_lists:
                    ref_warnings.append(f"ip-prefix {pl} 被引用但在输出中未找到定义")

        # route-map / prefix-list reference check (Cisco target)
        if tl == 'cisco':
            defined_rm = set(re.findall(
                r'^route-map\s+(\S+)', config_content, re.IGNORECASE | re.MULTILINE
            ))
            defined_pl = set(re.findall(
                r'^ip\s+prefix-list\s+(\S+)', config_content, re.IGNORECASE | re.MULTILINE
            ))
            referenced_rm = set(re.findall(
                r'route-map\s+(\S+)', config_content, re.IGNORECASE
            ))
            referenced_pl = set(re.findall(
                r'prefix-list\s+(\S+)', config_content, re.IGNORECASE
            ))
            for rm in referenced_rm:
                if rm not in defined_rm:
                    ref_warnings.append(f"route-map {rm} 被引用但在输出中未找到定义")
            for pl in referenced_pl:
                if pl not in defined_pl:
                    ref_warnings.append(f"prefix-list {pl} 被引用但在输出中未找到定义")

        # ACL / object-group reference check (ASA target)
        if tl == 'asa':
            defined_objects = set(re.findall(
                r'^object-group\s+\S+\s+(\S+)', config_content, re.IGNORECASE | re.MULTILINE
            ))
            defined_objects |= set(re.findall(
                r'^object\s+network\s+(\S+)', config_content, re.IGNORECASE | re.MULTILINE
            ))
            referenced_objects = set(re.findall(
                r'object-group\s+(\S+)', config_content, re.IGNORECASE
            ))
            referenced_objects |= set(re.findall(
                r'access-group\s+(\S+)', config_content, re.IGNORECASE
            ))
            for obj in referenced_objects:
                if obj not in defined_objects:
                    ref_warnings.append(f"object-group {obj} 被引用但在输出中未找到定义")

        # Cisco target: access-list references in access-group
        if tl == 'cisco':
            defined_acls = set(re.findall(
                r'^access-list\s+(\S+)', config_content, re.IGNORECASE | re.MULTILINE
            ))
            defined_acls |= set(re.findall(
                r'^ip\s+access-list\s+(?:standard|extended)\s+(\S+)',
                config_content,
                re.IGNORECASE | re.MULTILINE,
            ))
            referenced_acls = set(re.findall(
                r'access-group\s+(\S+)', config_content, re.IGNORECASE
            ))
            for acl in referenced_acls:
                if acl not in defined_acls:
                    ref_warnings.append(f"access-list {acl} 在 access-group 中被引用但未找到定义")

        # H3C target: ip ip-prefix + route-policy cross-reference
        if tl == 'h3c':
            defined_policies = set(re.findall(
                r'^route-policy\s+(\S+)', config_content, re.IGNORECASE | re.MULTILINE
            ))
            defined_prefix_lists = set(re.findall(
                r'^ip\s+ip-prefix\s+(\S+)', config_content, re.IGNORECASE | re.MULTILINE
            ))
            referenced_policies = set(re.findall(
                r'route-policy\s+(\S+)', config_content, re.IGNORECASE
            ))
            referenced_prefix_lists = set(re.findall(
                r'ip-prefix\s+(\S+)', config_content, re.IGNORECASE
            ))
            for rp in referenced_policies:
                if rp not in defined_policies:
                    ref_warnings.append(f"route-policy {rp} 被引用但在输出中未找到定义")
            for pl in referenced_prefix_lists:
                if pl not in defined_prefix_lists:
                    ref_warnings.append(f"ip-prefix {pl} 被引用但在输出中未找到定义")

        return ref_warnings

    def _platform_validation(self, config_content: str, to_vendor: str, source_vendor: str = "") -> list:
        warnings = []
        tl = to_vendor.lower()
        scan_content = self._executable_config_content(config_content)

        # ── Layer 1: Source-vendor residues (critical → deployable=false) ──
        # These are patterns from a DIFFERENT vendor that leaked into target output.
        residue = {
            'cisco': [
                # Huawei/H3C residues in IOS
                (r'\bsecurity-zone\b', 'Huawei/H3C: security-zone'),
                (r'\bsecurity-policy\b', 'Huawei/H3C: security-policy'),
                (r'\broute-policy\b', 'Huawei/H3C: route-policy'),
                (r'\bip\s+ip-prefix\b', 'Huawei/H3C: ip ip-prefix'),
                (r'\bimport-route\b', 'Huawei/H3C: import-route'),
                (r'\bnat\s+outbound\b', 'Huawei/H3C: nat outbound'),
                (r'\binfo-center\b', 'Huawei/H3C: info-center'),
                (r'\blocal-user\b', 'Huawei/H3C: local-user'),
                (r'\bundo\s+shutdown\b', 'Huawei/H3C: undo shutdown'),
                (r'\bport\s+link-mode\b', 'H3C: port link-mode'),
                (r'\baclnumber\b', 'Huawei/H3C: acl number'),
                (r'\binterface\s+GE\d+', 'Huawei/H3C: GE abbreviated interface'),
                (r'\binterface\s+XGigabitEthernet\d+', 'Huawei/H3C: XGigabitEthernet abbreviation'),
                (r'\b(irf\s+member|irf-port)\b', 'H3C: irf member/irf-port'),
                (r'\blacp-static\b', 'H3C: lacp-static'),
            ],
            'huawei': [
                # Cisco residues in Huawei VRP
                (r'\broute-map\b', 'Cisco: route-map'),
                (r'\bip\s+prefix-list\b', 'Cisco: ip prefix-list'),
                (r'\bip\s+nat\s+inside\s+source\b', 'Cisco: ip nat inside source'),
                (r'\bip\s+nat\s+inside\s+list\b', 'Cisco: ip nat inside list'),
                (r'\baccess-group\b', 'Cisco/ASA: access-group'),
                (r'\bobject\s+network\b', 'Cisco/ASA: object network'),
                (r'\bobject-group\b', 'Cisco/ASA: object-group'),
                (r'\bnameif\b', 'Cisco/ASA: nameif'),
                (r'\bsecurity-level\b', 'Cisco/ASA: security-level'),
                (r'\bchannel-group\b', 'Cisco: channel-group'),
                (r'\bip\s+dhcp\s+pool\b', 'Cisco: ip dhcp pool'),
                (r'\bdefault-information\s+originate\b', 'Cisco: default-information originate'),
                (r'\brouter\s+(ospf|bgp|rip)\b', 'Cisco: router {ospf|bgp|rip}'),
                (r'\bstandby\s+\d+', 'Cisco: standby (HSRP)'),
                (r'\bno\s+shutdown\b', 'Cisco: no shutdown'),
            ],
            'h3c': [
                # Cisco residues in H3C Comware
                (r'\broute-map\b', 'Cisco: route-map'),
                (r'\bip\s+prefix-list\b', 'Cisco: ip prefix-list'),
                (r'\bip\s+nat\s+inside\s+source\b', 'Cisco: ip nat inside source'),
                (r'\bip\s+nat\s+inside\s+list\b', 'Cisco: ip nat inside list'),
                (r'\baccess-group\b', 'Cisco/ASA: access-group'),
                (r'\bobject\s+network\b', 'Cisco/ASA: object network'),
                (r'\bobject-group\b', 'Cisco/ASA: object-group'),
                (r'\bnameif\b', 'Cisco/ASA: nameif'),
                (r'\bsecurity-level\b', 'Cisco/ASA: security-level'),
                (r'\bchannel-group\b', 'Cisco: channel-group'),
                (r'\bip\s+dhcp\s+pool\b', 'Cisco: ip dhcp pool'),
                (r'\bdefault-information\s+originate\b', 'Cisco: default-information originate'),
                (r'\bstandby\s+\d+', 'Cisco: standby (HSRP)'),
                (r'\bno\s+shutdown\b', 'Cisco: no shutdown'),
            ],
            'asa': [
                # IOS residues in ASA
                (r'\brouter\s+ospf\b', 'IOS: router ospf'),
                (r'\brouter\s+bgp\b', 'IOS: router bgp'),
                (r'\brouter\s+rip\b', 'IOS: router rip'),
                (r'\bip\s+nat\s+inside\s+source\b', 'IOS: ip nat inside source'),
                (r'\bip\s+nat\s+inside\s+list\b', 'IOS: ip nat inside list'),
                (r'\bip\s+route\b', 'IOS: ip route'),
                (r'\broute-map\b', 'IOS: route-map'),
                (r'\bip\s+prefix-list\b', 'IOS: ip prefix-list'),
                (r'\binterface\s+Ethernet\d+', 'IOS: interface Ethernet'),
                # Huawei/H3C residues in ASA
                (r'\bnat\s+static\s+enable\b', 'Huawei/H3C: nat static enable'),
                (r'\bnat\s+source\b', 'Huawei/H3C: nat source'),
                (r'\bnat\s+server\b', 'Huawei/H3C: nat server'),
                (r'\bnat\s+outbound\b', 'Huawei/H3C: nat outbound'),
                (r'\bsecurity-zone\b', 'Huawei/H3C: security-zone'),
                (r'\bsecurity-policy\b', 'Huawei/H3C: security-policy'),
                (r'\broute-policy\b', 'Huawei/H3C: route-policy'),
                (r'\bundo\s+shutdown\b', 'Huawei/H3C: undo shutdown'),
            ],
        }

        for pat, desc in residue.get(tl, []):
            if re.search(pat, scan_content, re.IGNORECASE):
                warnings.append(f"源厂商残留 — {desc}")

        # ── Layer 2: Style / lint patterns (non-critical) ──
        style = {
            'huawei': [
                (r'interface\s+Ethernet\d+', '华为建议使用 GigabitEthernet 而非 Ethernet'),
                (r'ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+secondary',
                 '华为 VRP 不支持 secondary IP'),
                (r'interface\s+Null\d+', '华为 VRP 不支持 Null 接口'),
                (r'acl\s+name\s+', '华为 VRP 使用 acl name 时注意 name 前面无需 number'),
                (r'interface\s+Vlanif\d+\s+ip\s+address\s+\S+\s+\S+\s+sub',
                 '华为 VRP 子接口 IP 使用 correct syntax'),
            ],
            'cisco': [
                (r'interface\s+GE\d+', 'Cisco IOS 通常使用 GigabitEthernet 而非 GE'),
                (r'interface\s+XGigabitEthernet\d+', 'Cisco IOS 通常使用 TenGigabitEthernet'),
                (r'ip\s+address\s+\S+\s+\S+\s+secondary', 'Cisco IOS 多个 IP 需确认是否使用 secondary'),
                (r'no\s+shut$', 'Cisco IOS 建议使用 no shutdown 而非 no shut'),
            ],
            'h3c': [
                (r'ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+secondary',
                 'H3C Comware 不支持 secondary IP'),
                (r'interface\s+XGigabitEthernet\d+', 'H3C 建议 Ten-GigabitEthernet 而非简写'),
                (r'ospf\s+\d+\s+router-id\s+', 'H3C OSPF router-id 命令位置需确认'),
            ],
            'asa': [
                (r'interface\s+Vlan\d+', 'ASA 子接口使用 interface <name>.<vlanid>'),
                (r'no\s+shutdown', 'ASA 使用 no shut 而非 no shutdown'),
                (r'interface\s+GigabitEthernet\d+/\d+', 'ASA 接口命名通常不带槽位号'),
            ],
        }
        for pat, desc in style.get(tl, []):
            if re.search(pat, scan_content, re.IGNORECASE):
                warnings.append(desc)

        # ── Layer 3: Structure checks (known error-prone formats) ──
        # VRF route-target / rd format (Cisco IOS)
        if tl == 'cisco':
            for rt in re.finditer(
                r'^\s*(?:rd\s+(\S+)|route-target\s+(?:export\s+|import\s+|both\s+)?(\S+))',
                scan_content,
                re.IGNORECASE | re.MULTILINE,
            ):
                val = rt.group(1) or rt.group(2)
                if ':' not in val:
                    warnings.append(f"VRF RD/route-target 格式异常（缺少冒号）: {val}")

        # ACL number range (Huawei/H3C)
        if tl in ('huawei', 'h3c'):
            for m in re.finditer(r'acl\s+number\s+(\d+)', scan_content, re.IGNORECASE):
                num = int(m.group(1))
                if 2000 <= num <= 2999:
                    pass  # basic ACL — valid
                elif 3000 <= num <= 3999:
                    pass  # advanced ACL — valid
                else:
                    warnings.append(f"ACL number {num} 超出华为/华三规格（基础 2000-2999，高级 3000-3999）")

        # IP prefix name format (Cisco)
        if tl == 'cisco':
            for m in re.finditer(r'ip\s+prefix-list\s+(\S+)', scan_content, re.IGNORECASE):
                name = m.group(1)
                if len(name) > 64:
                    warnings.append(f"prefix-list 名称 '{name}' 超长（最大 64 字符）")

        # Interface name format consistency (Huawei)
        if tl == 'huawei':
            gigs = re.findall(r'interface\s+GigabitEthernet(\d+/\d+/\d+)', scan_content)
            eths = re.findall(r'interface\s+Ethernet(\d+/\d+/\d+)', scan_content)
            if gigs and eths:
                warnings.append("华为 VRP 接口类型混用（GigabitEthernet + Ethernet），建议统一")

        # OSPF area format check: Cisco-style "network <ip> <wildcard> area <id>" in Huawei/H3C target
        if tl in ('huawei', 'h3c'):
            for m in re.finditer(r'(?:^|\n)\s*network\s+\S+\s+\S+\s+area\s+\d', scan_content):
                warnings.append(f"OSPF area 格式异常 — 检测到 Cisco 风格 'network <ip> <wildcard> area <id>'，华为/华三应使用 area <id> 视图下的 network 命令")

        # Reference checks
        ref_warnings = self._resolve_references(scan_content, to_vendor)
        warnings.extend(ref_warnings)

        return warnings

    @staticmethod
    def _executable_config_content(config_content: str) -> str:
        """Return only executable config lines for residue/style checks.

        Fallback output intentionally stores source commands in comments such as
        ``! MANUAL_REVIEW unsupported source command: ...``. Those comments are
        audit evidence, not executable residue, so platform validation should
        not treat them as leaked target configuration.
        """
        lines = []
        for raw in (config_content or "").splitlines():
            stripped = raw.strip()
            if not stripped or stripped.startswith(("!", "#", "//")):
                continue
            lines.append(raw)
        return "\n".join(lines)

    # ── Feature → expected output patterns for consistency check ──
    # Each entry: (pattern_regex, label)
    # If NONE of the patterns match in translated output, a warning is raised.
    FEATURE_OUTPUT_PATTERNS = {
        "nat": [(r"\bnat\b", "NAT"), (r"\bstatic\b.*\bdestination\b", "destination static"), (r"MANUAL_REVIEW", "manual review")],
        "route_policy": [(r"\broute-map\b", "route-map"), (r"\bprefix-list\b", "prefix-list"), (r"MANUAL_REVIEW", "manual review")],
        "ipsec": [(r"\bcrypto\s+map\b", "crypto map"), (r"\bipsec\b", "IPsec"), (r"MANUAL_REVIEW", "manual review")],
        "qos": [(r"\bclass-map\b", "class-map"), (r"\bpolicy-map\b", "policy-map"), (r"\btraffic\s+classifier\b", "traffic classifier"), (r"MANUAL_REVIEW", "manual review")],
        "bfd": [(r"\bbfd\b", "BFD"), (r"MANUAL_REVIEW", "manual review")],
        "acl": [(r"\baccess-list\b", "access-list"), (r"\baclnumber\b", "ACL number"), (r"\brule\b", "rule"), (r"MANUAL_REVIEW", "manual review")],
        "security_policy": [(r"\bsecurity-policy\b", "security-policy"), (r"\bzone-pair\b", "zone-pair"), (r"MANUAL_REVIEW", "manual review")],
        "tunnel": [(r"\binterface\s+Tunnel\b", "interface Tunnel"), (r"\btunnel\s+(mode|source|destination)\b", "tunnel mode/src/dst"), (r"MANUAL_REVIEW", "manual review")],
        "dhcp": [(r"\bip\s+dhcp\s+pool\b", "ip dhcp pool"), (r"\bdhcpserver\b", "DHCP server"), (r"MANUAL_REVIEW", "manual review")],
        "vrrp": [(r"\bvrrp\b", "VRRP"), (r"\bstandby\s+\d+", "standby"), (r"MANUAL_REVIEW", "manual review")],
        "lacp": [(r"\bport-channel", "Port-channel"), (r"\beth-trunk", "Eth-Trunk"), (r"\bbridge-aggregation", "Bridge-Aggregation"), (r"MANUAL_REVIEW", "manual review")],
        "stp": [(r"\bspanning-tree\b", "spanning-tree"), (r"\bstp\b", "STP"), (r"\bmst\b", "MST"), (r"MANUAL_REVIEW", "manual review")],
        "object": [(r"\bobject-group\b", "object-group"), (r"\bobject\s+(network|service)\b", "object network/service"), (r"MANUAL_REVIEW", "manual review")],
        "vrf": [(r"\bvrf\s+forwarding\b", "vrf forwarding"), (r"\bip\s+vpn-instance\b", "ip vpn-instance"), (r"\broute-distinguisher\b", "route-distinguisher"), (r"MANUAL_REVIEW", "manual review")],
    }

    # Consistency failures for these features affect deployability
    HIGH_RISK_CONSISTENCY_FEATURES = {"nat", "security_policy", "ipsec", "route_policy", "acl"}

    def _consistency_check(self, state: State, translated: str) -> tuple:
        """Check that analyzer findings are addressed in translated output.

        Returns (warnings: list[str], has_high_risk: bool) where has_high_risk
        is True when a high-risk feature is missing from output without MANUAL_REVIEW.
        """
        analyzer_results = _normalize_analyzer_results(state)
        warnings = []
        has_high_risk = False
        for feature_key, analysis in analyzer_results.items():
            if not isinstance(analysis, dict):
                continue
            status = analysis.get("status", "")
            risk = analysis.get("risk_level", "none")
            if status != "analyzed" or risk in ("none", "info"):
                continue
            patterns = self.FEATURE_OUTPUT_PATTERNS.get(feature_key, [])
            if not patterns:
                continue
            matched = any(re.search(p[0], translated, re.IGNORECASE) for p in patterns)
            if not matched:
                is_high = feature_key in self.HIGH_RISK_CONSISTENCY_FEATURES
                warnings.append(
                    f"[consistency:{feature_key}] 分析器发现 {risk} 风险 "
                    f"但翻译结果中未找到对应输出（{feature_key}）{'，将影响可部署性' if is_high else ''}，建议人工确认"
                )
                if is_high:
                    has_high_risk = True
        return warnings, has_high_risk

    def _check_stp_root_role(self, source_config: str, translated: str) -> list:
        """Check STP root primary/root secondary/priority semantics preserved.

        Returns list of warning strings (empty if OK).
        """
        source_has_root_role = bool(
            re.search(r'root\s+primary', source_config, re.IGNORECASE) or
            re.search(r'root\s+secondary', source_config, re.IGNORECASE) or
            re.search(r'spanning-tree\s+(?:mst\s+\d+|vlan\s+\d+)\s+priority\s+\d+', source_config, re.IGNORECASE) or
            re.search(r'stp\s+(?:instance\s+\d+)?\s*priority\s+\d+', source_config, re.IGNORECASE)
        )
        if not source_has_root_role:
            return []

        target_has_root_role = bool(
            re.search(r'root\s+primary', translated, re.IGNORECASE) or
            re.search(r'root\s+secondary', translated, re.IGNORECASE) or
            re.search(r'stp\s+(?:instance\s+\d+)?\s*priority\s+\d+', translated, re.IGNORECASE) or
            re.search(r'priority\s+\d+', translated, re.IGNORECASE) or
            re.search(r'MANUAL_REVIEW', translated)
        )
        if target_has_root_role:
            return []

        return [f"STP root role: 源配置包含根桥/优先级语义, 但目标输出缺少 root primary/root priority/MANUAL_REVIEW"]

    def _check_bgp_policy_refs(self, source_config: str, translated: str, to_vendor: str) -> list:
        """Check BGP route-policy/prefix-list cross-references are preserved.

        Returns list of warning strings (empty if OK).
        """
        ref_names = set()

        for m in re.finditer(r'(?:neighbor|peer)\s+\S+\s+(?:route-map|route-policy|prefix-list|ip-prefix)\s+(\S+)', source_config, re.IGNORECASE):
            ref_names.add(m.group(1))

        for m in re.finditer(r'prefix-list\s+(\S+)', source_config, re.IGNORECASE):
            ref_names.add(m.group(1))

        for m in re.finditer(r'filter-list\s+(\S+)', source_config, re.IGNORECASE):
            ref_names.add(m.group(1))

        if not ref_names:
            return []

        is_cisco_target = to_vendor == "cisco"
        if is_cisco_target:
            def_patterns = [
                (r'route-map\s+(\S+)', 'route-map'),
                (r'ip\s+prefix-list\s+(\S+)', 'ip prefix-list'),
            ]
        else:
            def_patterns = [
                (r'route-policy\s+(\S+)', 'route-policy'),
                (r'ip\s+ip-prefix\s+(\S+)', 'ip ip-prefix'),
            ]

        defined_names = set()
        for pat, _ in def_patterns:
            for m in re.finditer(pat, translated, re.IGNORECASE):
                defined_names.add(m.group(1))

        missing = ref_names - defined_names
        if not missing:
            return []

        has_manual_review = 'MANUAL_REVIEW' in translated.upper()

        warnings = []
        for name in sorted(missing):
            label = 'route-map/prefix-list' if is_cisco_target else 'route-policy/ip-prefix'
            warnings.append(
                f"BGP policy ref: 源配置引用了 {label} 「{name}」, "
                f"但目标输出中未找到对应定义"
            )
        if has_manual_review:
            warnings.append(
                "BGP policy ref: 目标输出含 MANUAL_REVIEW, 标记为人工确认"
            )
        return warnings

    def _collect_risk_signals(
        self,
        state: State,
        result,
        config_content: str,
        source_config: str,
        to_vendor: str,
        features: list,
    ) -> dict:
        signals = []
        analyzer_results = _normalize_analyzer_results(state)
        gap_severity = state.get("capability_gap_severity", "info")
        capabilities = state.get("capability_gaps", [])

        # Analyzer signals
        for feature_key, analysis in analyzer_results.items():
            if not isinstance(analysis, dict):
                continue
            risk = analysis.get("risk_level", "none")
            if risk in ("none", "info"):
                continue
            severity = RiskSeverity.WARNING if risk == "warning" else RiskSeverity.FATAL
            s = RiskSignal(
                source=RiskSource.ANALYZER,
                feature=feature_key,
                severity=severity,
                message=analysis.get("summary", f"{feature_key}: {risk}"),
                deployability_impact=feature_key in HIGH_RISK_FEATURES and severity != RiskSeverity.INFO,
                manual_review_impact=feature_key in HIGH_RISK_FEATURES,
            )
            signals.append(s)

        # Capability gap signals
        for gap in capabilities:
            if isinstance(gap, dict):
                gsev = gap.get("severity", "info")
                if gsev in ("fatal", "warning"):
                    sev = RiskSeverity.FATAL if gsev == "fatal" else RiskSeverity.WARNING
                    signals.append(RiskSignal(
                        source=RiskSource.CAPABILITY,
                        feature=gap.get("feature", "unknown"),
                        severity=sev,
                        message=gap.get("suggestion", f"capability gap: {gap.get('status', 'unknown')}"),
                        deployability_impact=True,
                        manual_review_impact=True,
                    ))

        # Consistency check signals (analyzer findings not reflected in output)
        consistency_warnings, has_high_risk_consistency = self._consistency_check(state, config_content)
        for cw in consistency_warnings:
            feat_match = [f for f in HIGH_RISK_FEATURES if f in cw]
            feat = feat_match[0] if feat_match else "unknown"
            signals.append(RiskSignal(
                source=RiskSource.CONSISTENCY,
                feature=feat,
                severity=RiskSeverity.WARNING,
                message=cw,
                deployability_impact=feat in HIGH_RISK_FEATURES,
                manual_review_impact=feat in HIGH_RISK_FEATURES,
            ))

        # Content quality signals
        content_errors, content_warnings = self._domain_validation(config_content, to_vendor, source_config)
        for ce in content_errors:
            signals.append(RiskSignal(
                source=RiskSource.CONTENT,
                feature="content",
                severity=RiskSeverity.FATAL,
                message=ce,
                deployability_impact=True,
                manual_review_impact=True,
            ))
        for cw in content_warnings:
            is_critical = any(kw in cw for kw in ["占位符", "<...>", "未替换", "todo", "placeholder", "待填充"])
            sev = RiskSeverity.FATAL if is_critical else RiskSeverity.WARNING
            signals.append(RiskSignal(
                source=RiskSource.CONTENT,
                feature="content",
                severity=sev,
                message=cw,
                deployability_impact=is_critical,
                manual_review_impact=True,
            ))

        # Platform validator signals
        platform_warnings = self._platform_validation(config_content, to_vendor)
        for pw in platform_warnings:
            is_residue = "源厂商残留" in pw or "残留" in pw
            signals.append(RiskSignal(
                source=RiskSource.PLATFORM,
                feature="platform",
                severity=RiskSeverity.WARNING,
                message=pw,
                deployability_impact=is_residue,
                manual_review_impact=True,
            ))

        # STP root role signals
        stp_warnings = self._check_stp_root_role(source_config, config_content)
        for sw in stp_warnings:
            signals.append(RiskSignal(
                source=RiskSource.VALIDATOR,
                feature="stp",
                severity=RiskSeverity.WARNING,
                message=sw,
                deployability_impact=True,
                manual_review_impact=True,
            ))

        # BGP policy ref signals
        bgp_warnings = self._check_bgp_policy_refs(source_config, config_content, to_vendor)
        for bw in bgp_warnings:
            signals.append(RiskSignal(
                source=RiskSource.VALIDATOR,
                feature="bgp",
                severity=RiskSeverity.WARNING,
                message=bw,
                deployability_impact=True,
                manual_review_impact=True,
            ))

        # MANUAL_REVIEW / MANUALLY_REVIEW marker in output
        if "MANUAL_REVIEW" in config_content.upper() or "MANUALLY_REVIEW" in config_content.upper():
            label = "MANUAL" if "MANUAL_REVIEW" in config_content.upper() else "MANUALLY"
            signals.append(RiskSignal(
                source=RiskSource.MANUAL_REVIEW,
                feature="output",
                severity=RiskSeverity.WARNING,
                message=f"翻译结果包含 {label}_REVIEW 标记",
                deployability_impact=True,
                manual_review_impact=True,
            ))

        # Critical content check (old path: combines all warnings)
        all_warnings = list(result.warnings) if hasattr(result, "warnings") else []
        critical_content = self._has_critical_content_warnings(all_warnings)
        if critical_content:
            signals.append(RiskSignal(
                source=RiskSource.CONTENT,
                feature="content",
                severity=RiskSeverity.WARNING,
                message="翻译结果包含关键内容问题（占位符/残留/引用断裂等）",
                deployability_impact=True,
                manual_review_impact=True,
            ))

        decision = decide_deployability(signals, features=features)

        return {
            "signals": [s.to_dict() for s in signals],
            "decision": decision,
            "gap_severity": gap_severity,
            "has_high_risk_consistency": has_high_risk_consistency,
            "critical_content": critical_content,
            "consistency_warnings": consistency_warnings,
            "stp_warnings": stp_warnings,
            "bgp_warnings": bgp_warnings,
            "content_errors": content_errors,
            "content_warnings": content_warnings,
            "platform_warnings": platform_warnings,
        }

    def _feature_validation(self, state: State, result) -> dict:
        gap_severity = state.get("capability_gap_severity", "info")
        analyzer_results = _normalize_analyzer_results(state)
        analyzer_fatal = False
        analyzer_warning = False
        high_risk_warning = False
        for feature_key, analysis in analyzer_results.items():
            if isinstance(analysis, dict):
                risk = analysis.get("risk_level", "none")
                if risk == "fatal":
                    analyzer_fatal = True
                    result.errors.append(f"[analyzer:{feature_key}] {analysis.get('summary', '高风险')}")
                elif risk == "warning":
                    analyzer_warning = True
                    high_risk_warning = True
                    result.warnings.append(f"[analyzer:{feature_key}] {analysis.get('summary', '中风险')}")

        if gap_severity == "warning":
            high_risk_warning = True

        return {
            "gap_severity": gap_severity,
            "analyzer_fatal": analyzer_fatal,
            "analyzer_warning": analyzer_warning,
            "high_risk_warning": high_risk_warning,
        }

    def _has_critical_content_warnings(self, warnings: list) -> bool:
        critical_patterns = [
            "占位符", "<...>", "未替换",
            "todo", "placeholder", "待填充",
            "源厂商残留", "残留",
            "缺少源",
            "Cisco 风格", "格式异常",
            "STP root role",
            "BGP policy ref",
        ]
        for w in warnings:
            wl = w.lower()
            if any(p.lower() in wl for p in critical_patterns):
                return True
        return False

    def _evaluate_deployability(self, validation_level: str, high_risk_warning: bool,
                                 critical_content_warning: bool,
                                 features: Optional[list] = None) -> dict:
        if validation_level == "fatal":
            return {"deployable": False, "manual_review_required": True}
        if high_risk_warning or critical_content_warning:
            return {"deployable": False, "manual_review_required": True}
        if validation_level == "warning":
            return {"deployable": True, "manual_review_required": True}
        return {"deployable": True, "manual_review_required": False}

    def execute(self, state: State) -> NodeResult:
        translated = state.get("translated_config", "")
        to_vendor = state.get("to_vendor", "unknown")
        source_config = state.get("config_text", "")

        if not translated:
            result = ValidationResult(valid=False, errors=["missing translated_config"])
            state.set("validation_result", result)
            output = {
                "valid": False, "level": "fatal", "deployable": False,
                "manual_review_required": True,
                "errors": ["missing translated_config"], "warnings": [],
            }
            state.set("validation_level", "fatal")
            return NodeResult(self.node_id, NodeStatus.FAILED, output=output)

        config_content = extract_config_block(translated).strip()

        result, parsed = self._generic_validation(config_content, to_vendor)
        source_config = state.get("config_text", "")
        features = state.get("features", [])

        risk_info = self._collect_risk_signals(
            state, result, config_content, source_config, to_vendor, features,
        )
        decision = risk_info["decision"]

        for e in risk_info["content_errors"]:
            result.errors.append(e)
        for w in risk_info["content_warnings"]:
            result.warnings.append(w)
        for w in risk_info["platform_warnings"]:
            result.warnings.append(w)
        for w in risk_info["consistency_warnings"]:
            result.warnings.append(w)
        for w in risk_info["stp_warnings"]:
            result.warnings.append(w)
        for w in risk_info["bgp_warnings"]:
            result.warnings.append(w)

        state.set("validation_result", result)

        feat = self._feature_validation(state, result)

        validation_level = decision.validation_level
        if validation_level == "info":
            if not result.valid and len(result.errors) > 0:
                fatal_keywords = ["拒答", "refuse", "sorry", "cannot", "unable", "as an ai", "i am an ai",
                                 "i'm an ai", "i cannot", "i can't", "not able to",
                                 "目标厂商无直接等价命令", "不自动生成目标配置"]
                fatal_text = " ".join(result.errors + result.warnings).lower()
                is_empty_output = len(config_content) < 10
                if is_empty_output or any(k in fatal_text for k in fatal_keywords):
                    validation_level = "fatal"
                elif len(result.errors) > 0:
                    validation_level = "warning"

        output = {
            "valid": result.valid,
            "level": validation_level,
            "deployable": decision.deployable,
            "manual_review_required": decision.manual_review_required,
            "errors": [str(e) for e in result.errors],
            "warnings": [str(w) for w in result.warnings],
            "risk_signals": [s.to_dict() for s in decision.signals],
        }
        state.set("validation_level", validation_level)
        state.set("deployable", decision.deployable)
        state.set("manual_review_required", decision.manual_review_required)
        state.set("risk_signals", [s.to_dict() for s in decision.signals])
        return NodeResult(
            self.node_id,
            NodeStatus.SUCCESS if validation_level != "fatal" else NodeStatus.FAILED,
            output=output,
        )


class DiffNode(Node):
    def __init__(self, node_id: str = "diff"):
        super().__init__(node_id, "diff")
        self.differ = ConfigDiffer()

    def execute(self, state: State) -> NodeResult:
        original = state.get("config_text", "")
        translated = state.get("translated_config", "")
        from_vendor = state.get("from_vendor", "unknown")
        to_vendor = state.get("to_vendor", "unknown")
        if not original or not translated:
            return NodeResult(self.node_id, NodeStatus.SKIPPED, output="missing input or output")

        parser = ConfigParser()
        diffs = self.differ.diff(
            parser.parse(original, from_vendor),
            parser.parse(extract_config_block(translated), to_vendor),
        )
        lines = ["## Diff Report", ""]
        if not diffs:
            lines.append("(no major differences)")
        else:
            for item in diffs:
                lines.append(f"- **{item.diff_type}** @ {item.location}")
                lines.append(f"  original: `{item.original}`")
                lines.append(f"  translated: `{item.translated}`")
                if item.note:
                    lines.append(f"  note: {item.note}")
        report = "\n".join(lines)
        state.set("diff_report", report)
        return NodeResult(self.node_id, NodeStatus.SUCCESS, output=report)


class SemanticValidatorNode(Node):
    def __init__(self, node_id: str = "semantic_validate", llm: Optional[LLM] = None):
        super().__init__(node_id, "semantic_validate")
        self.llm = llm  # reserved, currently unused

    def execute(self, state: State) -> NodeResult:
        ir_translation = state.get("ir_translation", [])
        ir_compare = state.get("ir_compare", {})
        source_vendor = state.get("from_vendor", "unknown")
        target_vendor = state.get("to_vendor", "unknown")

        success_types = []
        fail_types = []
        matched = ir_compare.get("matched_blocks", []) if isinstance(ir_compare, dict) else []

        for m in matched:
            if m.get("match"):
                success_types.append(m.get("type", "unknown"))
            else:
                fail_types.append(m.get("type", "unknown"))

        total = len(ir_translation) if isinstance(ir_translation, list) else 0
        score = (len(success_types) / max(total, 1)) if total > 0 else 1.0

        source_vendor_residue = []
        if isinstance(ir_translation, list):
            for b in ir_translation:
                for line in b.get("translated_lines", []):
                    if source_vendor.lower() in line.lower():
                        source_vendor_residue.append(line.strip())

        notes = []
        if fail_types:
            notes.append(f"keyword overlap low for: {', '.join(fail_types)}")
        if source_vendor_residue:
            notes.append(f"source vendor residue detected ({len(source_vendor_residue)} lines)")

        output = {
            "score": round(score, 2),
            "matched_features": success_types,
            "missing_features": fail_types,
            "source_vendor_residue": source_vendor_residue[:5],
            "notes": notes,
        }

        state.set("semantic_validation", output)
        state.set("semantic_score", score)
        state.set("semantic_issues", notes)

        return NodeResult(
            self.node_id,
            NodeStatus.SUCCESS,
            output=output,
            metadata={"score": score, "features_matched": len(success_types), "features_missing": len(fail_types)},
        )


class CapabilityGapNode(Node):
    def __init__(self, node_id: str = "capability_gap"):
        super().__init__(node_id, "capability_gap")

    def execute(self, state: State) -> NodeResult:
        from tools.knowledge_manager import detect_features_from_config
        from core.capability import get_feature_status_for_translation, severity_for_status

        config_text = state.get("config_text", "")
        source_vendor = state.get("from_vendor", "unknown")
        target_vendor = state.get("to_vendor", "unknown")
        translated = state.get("translated_config", "")

        features = set(detect_features_from_config(config_text))

        parsed_config = state.get("parsed_config")
        if parsed_config is not None:
            if hasattr(parsed_config, "interfaces") and parsed_config.interfaces:
                features.add("interface")
            if hasattr(parsed_config, "vlans") and parsed_config.vlans:
                features.add("vlan")
            if hasattr(parsed_config, "acl_configs") and parsed_config.acl_configs:
                features.add("acl")

        ir_source = state.get("ir_source", [])
        if isinstance(ir_source, list):
            for block in ir_source:
                if isinstance(block, dict):
                    ftype = block.get("type", "").lower()
                    if ftype and ftype != "_meta":
                        features.add(ftype)
                elif hasattr(block, "type") and block.type:
                    ftype = block.type.lower()
                    if ftype != "_meta":
                        features.add(ftype)

        features = sorted(features)

        gaps = []

        # Per-granularity checks based on feature type
        def _find_as_numbers(txt):
            return re.findall(r'(?:remote-as|as-number)\s+(\d+)', txt, re.IGNORECASE)

        def _find_placeholders(txt):
            return re.findall(r'(<[^>]+>|AS_PLACEHOLDER|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)', txt)

        for feat in features:
            status = get_feature_status_for_translation(feat, source_vendor, target_vendor)
            severity = severity_for_status(status)

            gap = {
                "feature": feat,
                "source_vendor": source_vendor,
                "target_vendor": target_vendor,
                "status": status,
                "severity": severity,
                "suggestion": "",
                "source_lines": [],
                "details": {},
            }

            if status == "unsupported":
                gap["suggestion"] = "目标厂商不支持此功能，不自动生成目标配置"
            elif status == "partial":
                gap["suggestion"] = "可近似实现，但语义不完全一致"
            elif status == "unknown":
                gap["suggestion"] = "知识库未确认目标厂商支持状态，建议人工确认"

            if severity in ("fatal", "warning"):
                for line in config_text.splitlines():
                    if feat in line.lower():
                        gap["source_lines"].append(line.strip())
                if not gap["source_lines"]:
                    gap["source_lines"] = [f"(feature: {feat})"]

            if severity == "warning" and status == "unknown":
                gap["details"]["risk"] = "LLM 自行推测，需人工核查"

            gaps.append(gap)

        # Structured detail enrichment for specific features
        for gap in gaps:
            f = gap["feature"]
            if f == "bgp":
                src_as = _find_as_numbers(config_text)
                if src_as:
                    gap["details"]["source_as"] = src_as
                if status == "unknown":
                    gap["details"]["note"] = "BGP AS 号应与源一致，确认目标厂商 AS 号范围"
            elif f == "interface" and "ip address" in config_text.lower():
                gap["details"]["has_ip_address"] = True
            elif f in ("vrrp",):
                gap["details"]["note"] = "VRRP group ID 和优先级需人工核对"

        analyzer_results = _normalize_analyzer_results(state)
        for feature_key, analysis in analyzer_results.items():
            if isinstance(analysis, dict):
                risk = analysis.get("risk_level", "none")
                if risk in ("fatal", "warning"):
                    gaps.append({
                        "feature": f"analyzer:{feature_key}",
                        "source_vendor": source_vendor,
                        "target_vendor": target_vendor,
                        "status": "analyzer_risk",
                        "severity": risk,
                        "suggestion": analysis.get("summary", f"分析器检测到风险: {risk}"),
                        "source_lines": analysis.get("source_lines", []),
                        "details": analysis.get("details", {}),
                    })

        max_gap_severity = "info"
        for g in gaps:
            if g["severity"] == "fatal":
                max_gap_severity = "fatal"
                break
            if g["severity"] == "warning":
                max_gap_severity = "warning"

        state.set("capability_gaps", gaps)
        state.set("capability_gap_severity", max_gap_severity)
        state.set("capability_notes", [f"{g['feature']}: {g['status']} ({g['suggestion']})" for g in gaps])

        return NodeResult(
            self.node_id,
            NodeStatus.SUCCESS,
            output={"gaps": gaps, "max_severity": max_gap_severity},
            metadata={"gap_count": len(gaps), "max_severity": max_gap_severity},
        )


class RouterNode(Node):
    def __init__(self, node_id: str = "router", routes: Optional[Dict[str, str]] = None):
        super().__init__(node_id, "router")
        self.routes = routes or {}

    def execute(self, state: State) -> NodeResult:
        translate_output = state.get("translate_output")
        validation = state.get("validation_result")
        if validation and hasattr(validation, "valid") and not validation.valid:
            next_node = self.routes.get("failure", "fallback")
            decision = "failure"
        elif translate_output and len(str(translate_output)) > 10:
            next_node = self.routes.get("success", "validate")
            decision = "success"
            state.set("_route_outcome", "llm_success")
        else:
            next_node = self.routes.get("failure", "fallback")
            decision = "empty"
        state.set("_route_decision", decision)
        state.set("_next_node", next_node)
        return NodeResult(self.node_id, NodeStatus.SUCCESS, output={"route_to": next_node, "decision": decision})


class FallbackNode(Node):
    def __init__(self, node_id: str = "fallback", knowledge_dir: str = "knowledge_data"):
        super().__init__(node_id, "fallback")
        self.knowledge = KnowledgeRetriever(knowledge_dir)

    @staticmethod
    def _comment_prefix(to_vendor: str) -> str:
        if (to_vendor or "").lower() == "cisco":
            return "!"
        return "#"

    @staticmethod
    def _requires_safe_fallback(error: str, config_text: str) -> bool:
        error_text = str(error or "").lower()
        validation_markers = (
            "invalid translation result",
            "not valid translation",
            "第 0 项不是对象",
            "不是对象",
            "不包含 JSON 数组",
            "LLM 输出校验失败",
        )
        if any(marker.lower() in error_text for marker in validation_markers):
            return True
        executable_lines = [
            line for line in (config_text or "").splitlines()
            if line.strip() and not line.strip().startswith(("!", "#"))
        ]
        return len(executable_lines) >= 300

    @staticmethod
    def _friendly_fallback_reason(error: str) -> str:
        error_text = str(error or "")
        lower = error_text.lower()
        if (
            "LLM 输出校验失败" in error_text
            or "不是对象" in error_text
            or "不包含 JSON 数组" in error_text
            or "not valid translation" in lower
            or "invalid translation result" in lower
        ):
            return "LLM 输出不是结构化翻译结果，已切换到规则兜底"
        if "timeout" in lower or "timed out" in lower:
            return "LLM 请求超时，已切换到规则兜底"
        if "rate limit" in lower or "429" in lower:
            return "LLM 服务限流，已切换到规则兜底"
        if not error_text:
            return "未知原因，已切换到规则兜底"
        return error_text[:180]

    _COMMENT_MARKERS = ("!", "#", "*")

    _SENSITIVE_PATTERNS = [
        (re.compile(r"(password\s+)irreversible-cipher\s+\S+", re.IGNORECASE), r"\1irreversible-cipher <redacted>"),
        (re.compile(r"(password\s+)cipher\s+\S+", re.IGNORECASE), r"\1cipher <redacted>"),
        (re.compile(r"(shared-key\s+)cipher\s+\S+", re.IGNORECASE), r"\1cipher <redacted>"),
        (re.compile(r"(shared-key\s+(?!cipher)\S+)", re.IGNORECASE), r"\1<redacted>"),
        (re.compile(r"(secret\s+)cipher\s+\S+", re.IGNORECASE), r"\1cipher <redacted>"),
        (re.compile(r"(secret\s+(?!cipher|\d+|<redacted>)\S+)", re.IGNORECASE), r"\1<redacted>"),
        (re.compile(r"(snmp-server\s+community\s+)\S+((?:\s+\S+)*)", re.IGNORECASE), r"\1<redacted>\2"),
        (re.compile(r"(snmp-agent\s+community\s+)read\s+cipher\s+\S+", re.IGNORECASE), r"\1read cipher <redacted>"),
        (re.compile(r"(snmp-agent\s+community\s+)write\s+cipher\s+\S+", re.IGNORECASE), r"\1write cipher <redacted>"),
        (re.compile(r"(snmp-agent\s+community\s+)(?!read\s+cipher|write\s+cipher|<redacted>)\S+", re.IGNORECASE), r"\1<redacted>"),
        (re.compile(r"(community\s+)read\s+cipher\s+\S+", re.IGNORECASE), r"\1read cipher <redacted>"),
        (re.compile(r"(community\s+)write\s+cipher\s+\S+", re.IGNORECASE), r"\1write cipher <redacted>"),
        (re.compile(r"(community\s+(?!read\s+cipher|write\s+cipher|<redacted>)\S+)", re.IGNORECASE), r"\1<redacted>"),
        (re.compile(r"(key\s+)cipher\s+\S+", re.IGNORECASE), r"\1cipher <redacted>"),
        (re.compile(r"(key\s+(?!cipher)\S+)", re.IGNORECASE), r"\1<redacted>"),
        (re.compile(r"(auth-type\s+)\S+", re.IGNORECASE), r"\1<redacted>"),
        (re.compile(r"(encrypt-key\s+)\S+", re.IGNORECASE), r"\1<redacted>"),
        (re.compile(r"(radius\s+shared-key\s+)cipher\s+\S+", re.IGNORECASE), r"\1cipher <redacted>"),
        (re.compile(r"(radius\s+shared-key\s+(?!cipher)\S+)", re.IGNORECASE), r"\1<redacted>"),
        (re.compile(r"(pre-shared-key\s+)cipher\s+\S+", re.IGNORECASE), r"\1cipher <redacted>"),
        (re.compile(r"(pre-shared-key\s+(?!cipher))\S+", re.IGNORECASE), r"\1 <redacted>"),
        (re.compile(r"(password\s+\d+)\s+\S+", re.IGNORECASE), r"\1 <redacted>"),
        (re.compile(r"(secret\s+\d+)\s+\S+", re.IGNORECASE), r"\1 <redacted>"),
        (re.compile(r"(password\s+)(?!irreversible-cipher|cipher|\d+|<redacted>)\S+", re.IGNORECASE), r"\1<redacted>"),
        (re.compile(r"(secret\s+(?!cipher|\d+|<redacted>)\S+)", re.IGNORECASE), r"\1<redacted>"),
    ]

    _CATEGORY_GROUPS = {
        "管理面": {"aaa", "system"},
        "接口与 VLAN": {"interface", "vlan", "stp", "二层"},
        "ACL 与安全策略": {"acl", "firewall-object", "security-policy", "qos"},
        "路由协议": {"ospf", "bgp", "static-route", "route-policy", "route", "vrf", "rip", "is-is"},
        "防火墙对象": {"address-set", "service-set", "address-object", "service-object", "nat", "firewall"},
        "未支持能力": set(),
    }

    _UNKNOWN_KEYWORD_CATEGORY_MAP = {
        "ospf": "路由协议",
        "bgp": "路由协议",
        "rip": "路由协议",
        "is-is": "路由协议",
        "route-policy": "路由协议",
        "address-set": "防火墙对象",
        "service-set": "防火墙对象",
        "address-object": "防火墙对象",
        "service-object": "防火墙对象",
        "security-policy": "ACL 与安全策略",
        "firewall": "ACL 与安全策略",
        "nat": "防火墙对象",
        "radius": "管理面",
        "tacacs": "管理面",
        "ntp": "管理面",
        "snmp": "管理面",
        "logger": "管理面",
        "info-center": "管理面",
        "stelnet": "管理面",
        "ssh": "管理面",
        "pki": "管理面",
        "vrrp": "接口与 VLAN",
        "lacp": "接口与 VLAN",
    }

    _RISK_LEVELS = {
        "aaa": "高",
        "system": "中",
        "interface": "中",
        "vlan": "低",
        "stp": "低",
        "acl": "中",
        "firewall-object": "中",
        "security-policy": "中",
        "qos": "中",
        "ospf": "中",
        "bgp": "中",
        "static-route": "中",
        "route-policy": "中",
        "route": "中",
        "vrf": "中",
        "rip": "中",
        "is-is": "中",
        "address-set": "中",
        "service-set": "中",
        "address-object": "中",
        "service-object": "中",
        "nat": "中",
        "firewall": "中",
        "snmp": "中",
        "nqa": "低",
        "bfd": "低",
        "unknown": "低",
    }

    _REVIEW_REASONS = {
        "管理面": "涉及认证/授权/日志等关键控制面配置，语义可能因厂商而异，需人工确认",
        "接口与 VLAN": "二层/三层接口和 VLAN 配置在目标平台可能语义不同，需人工确认",
        "ACL 与安全策略": "访问控制列表和安全策略需人工确认目标平台对应关系",
        "路由协议": "路由协议配置（OSPF/BGP 等）需确认目标平台 AS/进程号映射",
        "防火墙对象": "防火墙对象（地址集/服务集/安全策略）需人工确认映射完整性",
        "未支持能力": "目标平台未确认支持此功能，建议人工确认是否需要迁移",
    }

    @classmethod
    def _redact_line(cls, line: str) -> str:
        result = line
        for pattern, replacement in cls._SENSITIVE_PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    @classmethod
    def _get_category_for_feature(cls, feature: str, block_lines: list[str] | None = None) -> str:
        if feature in ("unknown", ""):
            if block_lines:
                combined = " ".join(ln.lower() for ln in block_lines)
                for kw, cat in cls._UNKNOWN_KEYWORD_CATEGORY_MAP.items():
                    if kw in combined:
                        return cat
            return "未支持能力"
        for category, features in cls._CATEGORY_GROUPS.items():
            if feature in features:
                return category
        return "未支持能力"

    @classmethod
    def _get_risk_level(cls, feature: str) -> str:
        return cls._RISK_LEVELS.get(feature, "低")

    @classmethod
    def _get_review_reason(cls, category: str) -> str:
        return cls._REVIEW_REASONS.get(category, "目标平台未确认支持此功能，建议人工确认")

    @staticmethod
    def _block_sample_lines(block, max_lines: int = 3) -> list[str]:
        lines = [ln.strip() for ln in block.lines if ln.strip() and not ln.strip().startswith(FallbackNode._COMMENT_MARKERS)]
        return lines[:max_lines]

    def _manual_review_fallback(self, config_text: str, from_vendor: str, to_vendor: str, error: str) -> tuple[str, str]:
        from core.parser.block_splitter import split_config_by_feature, summarize_feature_blocks
        from core.module_graph import build_module_graph, translate_module_graph

        prefix = self._comment_prefix(to_vendor)
        blocks = split_config_by_feature(config_text, vendor=from_vendor)
        module_graph = build_module_graph(config_text, vendor=from_vendor)
        module_translation = translate_module_graph(module_graph, from_vendor, to_vendor)
        raw_summary = summarize_feature_blocks(blocks)
        module_summary: dict[str, int] = {}
        for module in module_graph.modules:
            module_summary[module.feature] = module_summary.get(module.feature, 0) + 1
        language = "cisco" if (to_vendor or "").lower() == "cisco" else (to_vendor or "text")
        friendly_reason = self._friendly_fallback_reason(error)

        lines = [f"```{language}"]
        lines.append(f"{prefix} MANUAL_REVIEW: 自动翻译未生成可验证结果，已阻止源厂商命令进入可执行配置。")

        category_groups: dict[str, list[tuple[str, int]]] = {
            "管理面": [],
            "接口与 VLAN": [],
            "ACL 与安全策略": [],
            "路由协议": [],
            "防火墙对象": [],
            "未支持能力": [],
        }

        for block in blocks:
            feature = block.feature
            block_lines = block.lines
            category = self._get_category_for_feature(feature, block_lines)
            category_groups[category].append((feature, 1))

        lines.append(f"{prefix}")
        lines.append(f"{prefix} 人工复核摘要：")
        for category in ("管理面", "接口与 VLAN", "ACL 与安全策略", "路由协议", "防火墙对象", "未支持能力"):
            items = category_groups.get(category, [])
            if not items:
                continue
            total_count = sum(cnt for _, cnt in items)
            sample_feature = items[0][0]
            risk = self._get_risk_level(sample_feature)
            reason = self._get_review_reason(category)
            lines.append(f"{prefix} - 【{category}】 {total_count} 个配置块 ⚠ {risk}风险。{reason}")
            sample_lines: list[str] = []
            for feat, _ in items:
                for block in blocks:
                    block_cat = self._get_category_for_feature(block.feature, block.lines)
                    if block.feature == feat and block_cat == category:
                        for raw_line in self._block_sample_lines(block, max_lines=3):
                            if len(sample_lines) >= 3:
                                break
                            sample_lines.append(raw_line)
                        break
                if len(sample_lines) >= 3:
                    break
            for s in sample_lines[:3]:
                redacted = self._redact_line(s[:100])
                lines.append(f"{prefix}   示例：{redacted}")

        lines.append("```")

        if module_translation.deployable_config:
            deployable_config = "\n".join(
                self._redact_line(det_line)
                for det_line in module_translation.deployable_config.splitlines()
            )
        else:
            deployable_config = f"{prefix} (无可部署配置，详见人工复核)"

        report = "\n".join(lines)

        metadata = {
            "source_vendor": from_vendor,
            "target_vendor": to_vendor,
            "fallback_reason": friendly_reason,
            "block_count": len(blocks),
            "feature_summary": dict(sorted(raw_summary.items())) if raw_summary else {},
            "module_summary": dict(sorted(module_summary.items())) if module_summary else {},
            "module_graph": module_graph.to_dict(),
            "module_translations": module_translation.to_dict(),
            "manual_review_config": module_translation.manual_review_config,
            "feature_blocks": [
                {
                    "feature": b.feature,
                    "start_line": b.start_line,
                    "end_line": b.end_line,
                    "line_count": len(b.lines),
                }
                for b in blocks
            ],
        }

        return report, deployable_config, metadata

    def execute(self, state: State) -> NodeResult:
        from_vendor = state.get("from_vendor", "unknown")
        to_vendor = state.get("to_vendor", "unknown")
        error = state.get("translate_error", "unknown error")

        # Prefer pre-parsed config for rule-based fallback
        parsed_config = state.get("parsed_config")
        if parsed_config is not None and hasattr(parsed_config, "raw_lines") and parsed_config.raw_lines:
            config_text = "\n".join(parsed_config.raw_lines)
        else:
            config_text = state.get("config_text", "")

        state.set("fallback_used", True)
        friendly_reason = self._friendly_fallback_reason(error)
        state.set("fallback_reason", friendly_reason)
        state.set("_raw_fallback_error", error)

        if self._requires_safe_fallback(error, config_text):
            translated, deployable, fb_meta = self._manual_review_fallback(config_text, from_vendor, to_vendor, error)
            state.set("translated_config", translated)
            state.set("deployable_config", deployable)
            state.set("block_count", fb_meta["block_count"])
            state.set("feature_summary", fb_meta["feature_summary"])
            state.set("module_summary", fb_meta["module_summary"])
            state.set("module_graph", fb_meta["module_graph"])
            state.set("module_translations", fb_meta["module_translations"])
            state.set("manual_review_config", fb_meta["manual_review_config"])
            state.set("source_vendor", fb_meta["source_vendor"])
            state.set("target_vendor", fb_meta["target_vendor"])
            state.set("_fallback_metadata", fb_meta)
            state.set("safe_fallback", True)
            state.set("manual_review_required", True)
            state.set("_route_outcome", "fallback_manual_review")
            return NodeResult(
                self.node_id,
                NodeStatus.SUCCESS,
                output=translated,
                metadata={"safe_fallback": True},
            )

        translated = RuleBasedTranslator().translate(config_text, from_vendor, to_vendor)
        if translated:
            state.set("translated_config", translated)
            deployable = extract_config_block(translated).strip()
            state.set("deployable_config", deployable or translated)
            state.set("_route_outcome", "fallback_success")
        return NodeResult(
            self.node_id,
            NodeStatus.SUCCESS,
            output=translated or "[fallback] translation failed",
        )


class CacheWriteNode(Node):
    def __init__(self, node_id: str = "cache_write", cache_dir: str = _CACHE_DIR):
        super().__init__(node_id, "cache_write")
        self.cache_dir = cache_dir

    def execute(self, state: State) -> NodeResult:
        key = state.get("_cache_key")
        if not key:
            return NodeResult(self.node_id, NodeStatus.SKIPPED, output="no cache key")

        if state.get("cache_hit"):
            return NodeResult(self.node_id, NodeStatus.SKIPPED, output="already cached")

        translated = state.get("translated_config", "")
        route_outcome = state.get("_route_outcome", "unknown")
        validation_level = state.get("validation_level", "info")
        fallback_used = state.get("fallback_used", False)

        fatal_keywords = ["拒答", "refuse", "sorry", "cannot", "unable", "as an ai", "i am an ai",
                         "i'm an ai", "i cannot", "i can't", "not able to"]
        has_refusal = any(k in translated.lower() for k in fatal_keywords)
        has_output = len(translated.strip()) > 10
        not_truncated = "..." not in translated[-20:] if translated else False

        should_cache = (
            has_output
            and route_outcome in ("llm_success", "fallback_success")
            and validation_level != "fatal"
            and not has_refusal
            and not_truncated
        )

        if not should_cache:
            return NodeResult(
                self.node_id, NodeStatus.SKIPPED,
                output={"cached": False, "reason": "conditions not met"},
            )

        try:
            path = os.path.join(self.cache_dir, f"{key}.json")
            os.makedirs(self.cache_dir, exist_ok=True)
            quality = "fallback" if fallback_used else "llm"
            ir_source_raw = state.get("ir_source", [])
            ir_source_serialized = []
            for b in ir_source_raw:
                if isinstance(b, dict):
                    ir_source_serialized.append(b)
                elif hasattr(b, "__dataclass_fields__"):
                    ir_source_serialized.append(asdict(b))
                else:
                    ir_source_serialized.append({"type": str(b)})
            data = {
                "translated_config": translated,
                "ir_translation": state.get("ir_translation", []),
                "ir_source": ir_source_serialized,
                "ir_compare": state.get("ir_compare", {}),
                "cache_quality": quality,
                "refreshable": fallback_used,
            }
            with open(path, "w") as f:
                json.dump(data, f)
            logger.info("Cache WRITE key=%s quality=%s refreshable=%s", key[:12], quality, fallback_used)
            return NodeResult(
                self.node_id, NodeStatus.SUCCESS,
                output={"cached": True, "key": key[:12], "quality": quality, "refreshable": fallback_used},
            )
        except Exception as exc:
            logger.warning("Cache write failed: %s", exc)
            return NodeResult(self.node_id, NodeStatus.FAILED, error=str(exc))


class MemoryNode(Node):
    def __init__(self, node_id: str = "memory", memory_dir: str = "memory_data"):
        super().__init__(node_id, "memory")
        self.episodic = EpisodicMemory(memory_dir)

    def execute(self, state: State) -> NodeResult:
        event = None
        try:
            event = TranslationEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                from_vendor=state.get("from_vendor", "unknown"),
                to_vendor=state.get("to_vendor", "unknown"),
                original_config=state.get("config_text", "")[:500],
                translated_config=state.get("translated_config", "")[:500],
                summary=(state.get("translated_config", "") or "")[:100],
                user=state.get("user", "anonymous"),
            )
            self.episodic.record(event)
            recorded = True
        except Exception:
            logger.warning("Failed to record translation event", exc_info=True)
            recorded = False
        return NodeResult(
            self.node_id,
            NodeStatus.SUCCESS,
            output={"recorded": recorded, "event_id": event.event_id if event else None},
        )
