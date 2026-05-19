# -*- coding: utf-8 -*-
"""
Graph Architecture - 节点图工作流引擎
仿 LangFlow：Node + Edge + Flow，数据在图中流动，支持条件分支

核心概念：
- Node: 执行单元（解析/翻译/校验/路由等）
- Edge: 有向边，连接节点，传递数据
- Graph: 节点图定义，包含多个 Node 和 Edge
- FlowExecutor: 图执行器，按边遍历，条件路由
- State: 执行状态，存储中间数据
"""

from __future__ import annotations
import uuid
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod


class NodeStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class EdgeCondition(Enum):
    DEFAULT = "default"        # 默认边
    ON_SUCCESS = "on_success"   # 成功后走这条边
    ON_FAILURE = "on_failure"   # 失败后走这条边
    ROUTER = "router"           # 路由边（根据条件选择）


@dataclass
class State:
    """执行状态 - 图中流动的数据容器"""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    data: Dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def set(self, key: str, value: Any):
        self.data[key] = value

    def has(self, key: str) -> bool:
        return key in self.data

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "data": self.data,
        }

    # ── Domain / vendor / platform convenience accessors ──────────────

    @property
    def source_vendor(self) -> str:
        return self.get("from_vendor", "unknown")

    @property
    def target_vendor(self) -> str:
        return self.get("to_vendor", "unknown")

    @property
    def source_domain(self) -> str:
        return self.get("source_domain", "unknown")

    @property
    def target_domain(self) -> str:
        return self.get("target_domain", "unknown")

    @property
    def source_platform(self) -> str:
        return self.get("source_platform", "")

    @property
    def target_platform(self) -> str:
        return self.get("target_platform", "")

    @property
    def features(self) -> list:
        return self.get("features", [])

    def set_domain_info(
        self,
        source_domain: str = "",
        source_platform: str = "",
        target_domain: str = "",
        target_platform: str = "",
        features: list = None,
    ):
        if source_domain:
            self.set("source_domain", source_domain)
        if source_platform:
            self.set("source_platform", source_platform)
        if target_domain:
            self.set("target_domain", target_domain)
        if target_platform:
            self.set("target_platform", target_platform)
        if features is not None:
            self.set("features", features)


@dataclass
class NodeResult:
    """节点执行结果"""
    node_id: str
    status: NodeStatus
    output: Any = None
    error: Optional[str] = None
    elapsed_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_success(self) -> bool:
        return self.status == NodeStatus.SUCCESS

    def is_failure(self) -> bool:
        return self.status == NodeStatus.FAILED


class Node(ABC):
    """节点基类"""

    def __init__(self, node_id: str, name: str = None):
        self.node_id = node_id
        self.name = name or node_id
        self.metadata: Dict[str, Any] = {}

    @abstractmethod
    def execute(self, state: State) -> NodeResult:
        """执行节点逻辑"""
        pass

    def validate(self, state: State) -> bool:
        """验证前置条件"""
        return True

    def __repr__(self):
        return f"<Node {self.node_id}>"


@dataclass
class Edge:
    """有向边 - 连接两个节点"""
    from_node: str          # 源节点 ID
    to_node: str            # 目标节点 ID
    condition: EdgeCondition = EdgeCondition.DEFAULT
    condition_fn: Optional[Callable[[State, NodeResult], bool]] = None  # 路由条件函数

    def should_traverse(self, state: State, prev_result: Optional[NodeResult]) -> bool:
        """判断是否应该走这条边"""
        if self.condition == EdgeCondition.DEFAULT:
            return True

        if self.condition == EdgeCondition.ON_SUCCESS:
            return prev_result is not None and prev_result.is_success()

        if self.condition == EdgeCondition.ON_FAILURE:
            return prev_result is not None and prev_result.is_failure()

        if self.condition == EdgeCondition.ROUTER and self.condition_fn:
            return self.condition_fn(state, prev_result)

        return False


class Graph:
    """节点图"""

    def __init__(self, name: str = "flow"):
        self.name = name
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self._outgoing: Dict[str, List[Edge]] = {}  # node_id -> outgoing edges
        self._incoming: Dict[str, List[Edge]] = {}  # node_id -> incoming edges

    def add_node(self, node: Node) -> Graph:
        self.nodes[node.node_id] = node
        self._outgoing[node.node_id] = []
        self._incoming[node.node_id] = []
        return self

    def add_edge(
        self,
        from_node: str,
        to_node: str,
        condition: EdgeCondition = EdgeCondition.DEFAULT,
        condition_fn: Optional[Callable[[State, NodeResult], bool]] = None,
    ) -> Graph:
        edge = Edge(
            from_node=from_node,
            to_node=to_node,
            condition=condition,
            condition_fn=condition_fn,
        )
        self.edges.append(edge)
        self._outgoing.setdefault(from_node, []).append(edge)
        self._incoming.setdefault(to_node, []).append(edge)
        return self

    def get_node(self, node_id: str) -> Optional[Node]:
        return self.nodes.get(node_id)

    def get_outgoing_edges(self, node_id: str) -> List[Edge]:
        return self._outgoing.get(node_id, [])

    def get_incoming_edges(self, node_id: str) -> List[Edge]:
        return self._incoming.get(node_id, [])

    def get_entry_nodes(self) -> List[str]:
        """获取入度为 0 的节点（入口节点）"""
        return [nid for nid, edges in self._incoming.items() if len(edges) == 0]

    def get_exit_nodes(self) -> List[str]:
        """获取出度为 0 的节点（出口节点）"""
        return [nid for nid, edges in self._outgoing.items() if len(edges) == 0]

    def visualize(self) -> str:
        """返回图的文本可视化"""
        lines = [f"Graph: {self.name}", "=" * 40]
        for node_id, node in self.nodes.items():
            outgoing = [e.to_node for e in self.get_outgoing_edges(node_id)]
            lines.append(f"  [{node_id}] -> {outgoing}")
        return "\n".join(lines)


class FlowExecutor:
    """图执行器 - 遍历图，执行节点，支持条件路由"""

    def __init__(self, graph: Graph):
        self.graph = graph
        self.history: List[NodeResult] = []

    def execute(self, state: State, start_node: str = None) -> State:
        """从入口节点开始执行"""
        if start_node is None:
            entries = self.graph.get_entry_nodes()
            if not entries:
                raise ValueError("No entry node in graph")
            start_node = entries[0]

        current_node_id = start_node
        visited = set()

        while current_node_id and current_node_id not in visited:
            visited.add(current_node_id)
            node = self.graph.get_node(current_node_id)

            if node is None:
                break

            # 执行节点
            t0 = time.time()
            try:
                node_result = node.execute(state)
            except Exception as exc:
                node_result = NodeResult(
                    current_node_id, NodeStatus.FAILED,
                    error=str(exc)[:500]
                )
            node_result.elapsed_ms = (time.time() - t0) * 1000
            self.history.append(node_result)

            # 将节点输出存入 state
            if node_result.output is not None:
                state.set(f"{current_node_id}_output", node_result.output)
            if node_result.error:
                state.set(f"{current_node_id}_error", node_result.error)

            # 检查是否需要重翻译（语义验证失败时）
            if state.get("need_retranslate") and current_node_id == "semantic_validate":
                state.set("need_retranslate", False)
                visited.discard("translate")
                visited.discard("router")
                visited.discard("semantic_validate")
                current_node_id = "translate"
                continue

            # 根据条件选择下一条边
            next_node_id = self._select_next_edge(current_node_id, state, node_result)
            current_node_id = next_node_id

        return state

    def _select_next_edge(self, node_id: str, state: State, prev_result: NodeResult) -> Optional[str]:
        """根据边的条件选择下一个节点"""
        outgoing = self.graph.get_outgoing_edges(node_id)

        for edge in outgoing:
            if edge.should_traverse(state, prev_result):
                return edge.to_node

        return None

    def get_results(self) -> List[NodeResult]:
        return self.history
