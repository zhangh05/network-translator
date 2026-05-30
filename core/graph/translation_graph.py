# -*- coding: utf-8 -*-
"""
Translation Graph - 翻译工作流图定义

  架构:
  ParseNode(规则解析)
      │
  FeatureAnalyzerNode(特征分析)
      │
  KnowledgeNode(特征检索 + 知识注入)
      │
  CacheNode(CacheRead — 只读, 不写)
      │
  TranslateNode(单次 LLM 调用)
      │
  RouterNode
   ├── success ─────────┐
   └── failure → Fallback ──┤
                          │
                    SemanticValidatorNode(informative)
                          │
                    CapabilityGapNode(能力缺口检测)
                          │
                    ValidateNode(三级: fatal/warning/info)
                          │
                    DiffNode(informative)
                          │
                    CacheWriteNode(校验通过后写缓存)
                          │
                    MemoryNode(统一持久化)
"""

from core.graph import Graph, EdgeCondition, State, FlowExecutor
from core.graph.nodes import (
    ParseNode, KnowledgeNode, CacheNode, TranslateNode,
    ValidateNode, DiffNode, RouterNode, FallbackNode, MemoryNode,
    SemanticValidatorNode, CacheWriteNode, CapabilityGapNode,
    FeatureAnalyzerNode,
)


def create_translation_graph(
    knowledge_dir: str = "knowledge_data",
    memory_dir: str = "memory_data",
    enable_diff: bool = True,
    enable_fallback: bool = True,
    llm=None,
    cache_dir: str = "",
) -> Graph:
    graph = Graph(name="translation_flow")

    # ── 节点 ────────────────────────────────────────────
    parse_node = ParseNode("parse")
    feature_analyzer_node = FeatureAnalyzerNode("feature_analyzer")
    knowledge_node = KnowledgeNode("knowledge", knowledge_dir)
    cache_kwargs = {"cache_dir": cache_dir} if cache_dir else {}
    cache_node = CacheNode("cache", **cache_kwargs)
    translate_node = TranslateNode("translate", llm=llm, knowledge_dir=knowledge_dir)
    semantic_validate_node = SemanticValidatorNode("semantic_validate", llm=llm)
    capability_gap_node = CapabilityGapNode("capability_gap")
    validate_node = ValidateNode("validate")
    diff_node = DiffNode("diff")
    memory_node = MemoryNode("memory", memory_dir)
    router_node = RouterNode(
        "router",
        routes={"success": "semantic_validate", "failure": "fallback"}
    )
    fallback_node = FallbackNode("fallback", knowledge_dir)
    cache_write_node = CacheWriteNode("cache_write", **cache_kwargs)

    graph.add_node(parse_node)
    graph.add_node(feature_analyzer_node)
    graph.add_node(knowledge_node)
    graph.add_node(cache_node)
    graph.add_node(translate_node)
    graph.add_node(semantic_validate_node)
    graph.add_node(capability_gap_node)
    graph.add_node(validate_node)
    graph.add_node(memory_node)
    graph.add_node(router_node)
    graph.add_node(fallback_node)
    graph.add_node(cache_write_node)
    if enable_diff:
        graph.add_node(diff_node)

    # ── 边 ──────────────────────────────────────────────
    # parse → feature_analyzer → knowledge → cache → translate → router
    graph.add_edge("parse", "feature_analyzer")
    graph.add_edge("feature_analyzer", "knowledge")
    graph.add_edge("knowledge", "cache")
    graph.add_edge("cache", "translate")
    graph.add_edge("translate", "router")

    # Router 分支
    graph.add_edge(
        "router", "semantic_validate",
        condition=EdgeCondition.ROUTER,
        condition_fn=lambda state, result: state.get("_route_decision") == "success",
    )
    graph.add_edge(
        "router", "fallback",
        condition=EdgeCondition.ROUTER,
        condition_fn=lambda state, result: state.get("_route_decision") in ("failure", "empty"),
    )

    # fallback 输出也进入后验证流程
    graph.add_edge("fallback", "semantic_validate")

    # PostValidateGroup: semantic → capability_gap → validate → diff → cache_write → memory
    graph.add_edge("semantic_validate", "capability_gap")
    graph.add_edge("capability_gap", "validate")
    if enable_diff:
        graph.add_edge("validate", "diff")
        graph.add_edge("diff", "cache_write")
    else:
        graph.add_edge("validate", "cache_write")
    graph.add_edge("cache_write", "memory")

    return graph


def execute_translation_flow(
    graph: Graph,
    config_text: str,
    from_vendor: str,
    to_vendor: str,
    user: str = "anonymous",
    source_domain: str = "",
    source_platform: str = "",
    target_domain: str = "",
    target_platform: str = "",
) -> dict:
    state = State()
    state.set("config_text", config_text)
    state.set("from_vendor", from_vendor)
    state.set("to_vendor", to_vendor)
    state.set("user", user)
    if source_domain:
        state.set("source_domain", source_domain)
    if source_platform:
        state.set("source_platform", source_platform)
    if target_domain:
        state.set("target_domain", target_domain)
    if target_platform:
        state.set("target_platform", target_platform)

    executor = FlowExecutor(graph)
    final_state = executor.execute(state)

    results = executor.get_results()

    translated = final_state.get("translated_config", "")
    deployable = final_state.get("deployable_config", "")
    diff_report = final_state.get("diff_report", "")
    validation = final_state.get("validation_result")
    fallback_used = final_state.get("fallback_used", False)
    route_decision = final_state.get("_route_decision", "unknown")

    validation_level = final_state.get("validation_level", "info")
    success = bool(
        translated and len(translated) > 10
        and not fallback_used
        and validation_level != "fatal"
    )

    semantic_validation = final_state.get("semantic_validation", {})
    semantic_issues = final_state.get("semantic_issues", [])

    return {
        "success": success,
        "translated": translated,
        "deployable_config": deployable,
        "diff": diff_report,
        "source_domain": final_state.get("source_domain", ""),
        "source_platform": final_state.get("source_platform", ""),
        "target_domain": final_state.get("target_domain", ""),
        "target_platform": final_state.get("target_platform", ""),
        "features": final_state.get("features", []),
        "module_summary": final_state.get("module_summary", {}),
        "module_graph": final_state.get("module_graph", {}),
        "analyzer_results": final_state.get("analyzer_results", []),
        "validation": {
            "valid": validation.valid if validation else False,
            "level": validation_level,
            "deployable": final_state.get("deployable", True),
            "manual_review_required": final_state.get("manual_review_required", False),
            "errors": [str(e) for e in validation.errors] if validation else [],
            "warnings": [str(w) for w in validation.warnings] if validation else [],
        } if validation else {
            "deployable": False,
            "manual_review_required": True,
        },
        "semantic_validation": semantic_validation,
        "capability_gaps": final_state.get("capability_gaps", []),
        "capability_gap_severity": final_state.get("capability_gap_severity", "info"),
        "capability_notes": final_state.get("capability_notes", []),
        "route_decision": route_decision,
        "fallback_used": fallback_used,
        "fallback_reason": final_state.get("fallback_reason", ""),
        "cache_hit": final_state.get("cache_hit", False),
        "risk_signals": final_state.get("risk_signals", []),
        "node_results": [
            {
                "node": r.node_id,
                "status": r.status.value,
                "elapsed_ms": round(r.elapsed_ms, 2),
                "error": r.error,
            }
            for r in results
        ],
    }
