# -*- coding: utf-8 -*-
"""
GraphAgent - 基于 Graph 架构的翻译智能体
替代 BaseAgent 单体架构，使用 Node + Edge + Flow 执行翻译
"""

from typing import Optional, Dict, Any
import hashlib

from core.graph import State
from core.graph.translation_graph import create_translation_graph, execute_translation_flow
from memory import WorkingMemory, EpisodicMemory, SemanticMemory
from core import get_llm, LLM


class GraphAgent:
    """
    图驱动翻译智能体

    使用 graph/translation_graph.py 定义的工作流图执行翻译，
    支持条件分支、错误恢复、多节点协作。
    """

    name = "GraphTranslator"
    description = "图驱动翻译智能体 - Node+Edge+Flow 架构"

    def __init__(
        self,
        knowledge_dir: str = "knowledge_data",
        memory_dir: str = "memory_data",
        enable_diff: bool = True,
        enable_fallback: bool = True,
        llm: Optional[LLM] = None,
        cache_dir: str = "",
    ):
        self.knowledge_dir = knowledge_dir
        self.memory_dir = memory_dir
        self.enable_diff = enable_diff
        self.enable_fallback = enable_fallback
        self.llm = llm if llm is not None else get_llm()
        self.cache_dir = cache_dir

        # 记忆系统
        self.working_memory = WorkingMemory(max_size=30, ttl_seconds=7200)
        self.episodic_memory = EpisodicMemory(memory_dir)
        self.semantic_memory = SemanticMemory(knowledge_dir)

        # 创建工作流图
        self.graph = create_translation_graph(
            knowledge_dir=knowledge_dir,
            memory_dir=memory_dir,
            enable_diff=enable_diff,
            enable_fallback=enable_fallback,
            llm=self.llm,
            cache_dir=cache_dir,
        )
        self._attach_agent_to_nodes()

    def _attach_agent_to_nodes(self):
        for node in self.graph.nodes.values():
            if hasattr(node, "agent"):
                node.agent = self

    def translate(
        self,
        config_text: str,
        from_vendor: str,
        to_vendor: str,
        user: str = "anonymous",
    ) -> str:
        result = self.run(
            config_text=config_text,
            from_vendor=from_vendor,
            to_vendor=to_vendor,
            user=user,
        )
        return result.get("translated", "")

    def run(
        self,
        config_text: str,
        from_vendor: str,
        to_vendor: str,
        user: str = "anonymous",
        source_domain: str = "",
        source_platform: str = "",
        target_domain: str = "",
        target_platform: str = "",
    ) -> Dict[str, Any]:
        """
        运行翻译工作流，返回完整结果

        返回: {
            "success": bool,
            "translated": str,
            "diff": str,
            "validation": dict,
            "route_decision": str,
            "node_results": [...],
        }
        """
        session_id = hashlib.sha256(config_text[:200].encode()).hexdigest()[:16]
        self.working_memory.set(f"{session_id}_from", from_vendor)
        self.working_memory.set(f"{session_id}_to", to_vendor)
        self.working_memory.set(f"{session_id}_config", config_text[:300])

        return execute_translation_flow(
            graph=self.graph,
            config_text=config_text,
            from_vendor=from_vendor,
            to_vendor=to_vendor,
            user=user,
            source_domain=source_domain,
            source_platform=source_platform,
            target_domain=target_domain,
            target_platform=target_platform,
        )

    def visualize(self) -> str:
        """返回工作流图的可视化"""
        return self.graph.visualize()
