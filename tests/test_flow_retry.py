from core.graph import Graph, Node, NodeResult, NodeStatus, State, FlowExecutor


class MarkNode(Node):
    def __init__(self, node_id: str, mark: str):
        super().__init__(node_id, node_id)
        self.mark = mark

    def execute(self, state: State) -> NodeResult:
        seq = state.get("seq", [])
        seq.append(self.mark)
        state.set("seq", seq)
        return NodeResult(node_id=self.node_id, status=NodeStatus.SUCCESS, output=self.mark)


class SemanticRetryNode(Node):
    def __init__(self):
        super().__init__("semantic_validate", "semantic_validate")

    def execute(self, state: State) -> NodeResult:
        seq = state.get("seq", [])
        seq.append("semantic")
        state.set("seq", seq)
        count = state.get("semantic_retry_count", 0)
        if count == 0:
            state.set("semantic_retry_count", 1)
            state.set("need_retranslate", True)
            return NodeResult(node_id=self.node_id, status=NodeStatus.FAILED, output="retry")
        return NodeResult(node_id=self.node_id, status=NodeStatus.SUCCESS, output="ok")


def test_flow_executor_reenters_semantic_validate_after_retry():
    graph = Graph(name="retry_flow")
    graph.add_node(MarkNode("parse", "parse"))
    graph.add_node(MarkNode("translate", "translate"))
    graph.add_node(MarkNode("router", "router"))
    graph.add_node(SemanticRetryNode())
    graph.add_node(MarkNode("memory", "memory"))

    graph.add_edge("parse", "translate")
    graph.add_edge("translate", "router")
    graph.add_edge("router", "semantic_validate")
    graph.add_edge("semantic_validate", "memory")

    state = State()
    executor = FlowExecutor(graph)
    end_state = executor.execute(state)

    seq = end_state.get("seq", [])
    assert seq.count("semantic") == 2
    assert seq[-1] == "memory"
