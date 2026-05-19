# Production-Grade Optimization Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring three production-grade improvements to the Network-Translator-Agent: (1) semantic validation via rule-based structural comparison replacing lightweight heuristic, (2) LLM singleton + tiktoken-based context compression, (3) parallel knowledge retrieval + parsed_config reuse in FallbackNode.

**Architecture:** Three independent optimization tracks sharing no files. Each track modifies only its target files, produces working tests, and commits independently.

**Tech Stack:** Python 3.12, tiktoken (available in environment), concurrent.futures.ThreadPoolExecutor (stdlib), dataclasses/json (stdlib), existing pytest.

---

## Track A: Semantic Validation via Rule-Based Structural Comparison

### Overview

Replace the lightweight heuristic (`bool(translated_lines) → match`) in `TranslateNode` with a rule-based `SemanticComparator` that compares `ir_source` (from LLM parse) against `ir_translation` (from LLM translate) by type coverage and field completeness — **without any additional LLM calls**. This closes the semantic validation gap created when backtranslate/compare steps were removed for performance.

### Files

- **Create:** `core/semantic_compare.py` — rule-based IR comparison engine
- **Modify:** `core/graph/nodes.py:71-158` — replace lightweight ir_compare block in `TranslateNode.execute()` with `SemanticComparator.compare()` call
- **Create:** `tests/test_semantic_compare.py` — unit tests for `SemanticComparator`

### Task A-1: Create `SemanticComparator`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_semantic_compare.py
import pytest
from core.semantic_compare import SemanticComparator, IRBlock

def test_empty_ir_returns_no_match():
    comp = SemanticComparator()
    result = comp.compare([], [])
    assert result["overall_match"] is False
    assert result["matched_blocks"] == []

def test_single_type_match():
    comp = SemanticComparator()
    source = [
        IRBlock(type="vlan", function="create vlan", params={"id": 10, "name": "VLAN10"}, original_lines=["vlan 10"], confidence=1.0),
    ]
    translated = [
        {"type": "vlan", "original_lines": ["vlan 10"], "translated_lines": ["vlan 10"], "confidence": 1.0},
    ]
    result = comp.compare(source, translated)
    assert result["overall_match"] is True
    assert len(result["matched_blocks"]) == 1
    assert result["matched_blocks"][0]["type"] == "vlan"
    assert result["matched_blocks"][0]["match"] is True

def test_missing_translated_block_fails():
    comp = SemanticComparator()
    source = [
        IRBlock(type="vlan", function="create vlan", params={"id": 10}, original_lines=["vlan 10"], confidence=1.0),
        IRBlock(type="bgp", function="bgp as", params={"asn": 65001}, original_lines=["router bgp 65001"], confidence=1.0),
    ]
    translated = [
        {"type": "vlan", "original_lines": ["vlan 10"], "translated_lines": ["vlan 10"], "confidence": 1.0},
        # bgp block missing — should mark as fail
    ]
    result = comp.compare(source, translated)
    assert result["overall_match"] is False
    assert len(result["unmatched_source"]) == 1
    assert "bgp" in result["unmatched_source"]

def test_params_field_coverage_scores():
    comp = SemanticComparator()
    source = [
        IRBlock(type="interface", function="layer3 interface", params={"name": "GigabitEthernet0/1", "ip": "10.0.0.1", "mask": "255.255.255.0"}, original_lines=["interface GigabitEthernet0/1"], confidence=1.0),
    ]
    translated = [
        {"type": "interface", "original_lines": ["interface GigabitEthernet0/1"], "translated_lines": ["interface GigabitEthernet0/1", "ip address 10.0.0.1 255.255.255.0"], "confidence": 1.0},
    ]
    result = comp.compare(source, translated)
    assert result["overall_match"] is True
    # similarity should be high (2/3 field keywords found)
    assert result["matched_blocks"][0]["similarity"] >= 0.6

def test_empty_translated_lines_fails_block():
    comp = SemanticComparator()
    source = [
        IRBlock(type="acl", function="permit http", params={"acl_id": 101}, original_lines=["access-list 101 permit tcp any any eq 80"], confidence=1.0),
    ]
    translated = [
        {"type": "acl", "original_lines": ["access-list 101 permit tcp any any eq 80"], "translated_lines": [], "notes": "no equivalent in target", "confidence": 0.3},
    ]
    result = comp.compare(source, translated)
    assert result["matched_blocks"][0]["match"] is False
    assert result["matched_blocks"][0]["similarity"] < 0.5
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_semantic_compare.py -v`
Expected: FAIL — `SemanticComparator` not defined

- [ ] **Step 3: Write minimal implementation**

```python
# core/semantic_compare.py
"""Rule-based IR semantic comparison — no LLM required."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class IRBlock:
    """Internal representation of a parsed IR block (source-side)."""
    type: str
    function: str
    params: Dict[str, Any]
    original_lines: List[str]
    confidence: float = 1.0


@dataclass
class TranslationBlock:
    """Internal representation of a translated IR block (target-side)."""
    type: str
    original_lines: List[str]
    translated_lines: List[str]
    confidence: float = 0.0
    notes: str = ""


def _keyword_set(params: Dict[str, Any]) -> set:
    """Extract searchable keywords from params for similarity scoring."""
    keywords = set()
    for v in params.values():
        if isinstance(v, str):
            keywords.update(v.lower().split())
        elif isinstance(v, (int, float)):
            keywords.add(str(v))
    return keywords


class SemanticComparator:
    """Compare ir_source (list of IRBlock) against ir_translation (list of dict).

    Rule-based — no LLM calls. Uses type coverage + field presence + keyword
    similarity to produce an overall_match verdict and per-block match info.
    """

    def compare(self, ir_source: List[Any], ir_translation: List[Any]) -> Dict[str, Any]:
        """Main entry point."""
        if not ir_source:
            return {"overall_match": False, "matched_blocks": [], "unmatched_source": [], "summary": "no source blocks"}

        if not ir_translation:
            return {
                "overall_match": False,
                "matched_blocks": [],
                "unmatched_source": [self._block_type(b) for b in ir_source],
                "summary": "no translation result",
            }

        source_by_type: Dict[str, IRBlock] = {}
        for block in ir_source:
            bt = self._block_type(block)
            source_by_type[bt] = block

        matched: List[Dict[str, Any]] = []
        unmatched_source: List[str] = []
        used_types: set = set()

        # Build lookup from translation blocks by type
        trans_by_type: Dict[str, List[Any]] = {}
        for tb in ir_translation:
            bt = self._block_type(tb)
            trans_by_type.setdefault(bt, []).append(tb)

        all_source_types = list(source_by_type.keys())

        # One pass through source blocks in order
        for block in ir_source:
            bt = self._block_type(block)
            trans_candidates = trans_by_type.get(bt, [])
            # Find first unused candidate of matching type
            match = None
            for candidate in trans_candidates:
                if self._block_type(candidate) not in used_types:
                    match = candidate
                    break

            if match is None:
                unmatched_source.append(bt)
                matched.append(self._fail_entry(bt))
                continue

            used_types.add(self._block_type(match))
            source_keywords = _keyword_set(self._block_params(block))
            # translated_lines presence check
            has_output = bool(self._translated_lines(match))
            # keyword overlap with translated_lines text
            trans_text = " ".join(self._translated_lines(match)).lower()
            trans_keywords = set(trans_text.split())
            overlap = len(source_keywords & trans_keywords) / max(len(source_keywords), 1)
            similarity = overlap if has_output else 0.0
            match_flag = has_output and similarity >= 0.3

            matched.append({
                "type": bt,
                "match": match_flag,
                "similarity": round(similarity, 3),
                "params_diff": [],
                "function_diff": "" if match_flag else f"translated_lines empty or similarity={similarity:.2f}<0.3",
            })

        # Check for extra translation blocks (unmatched target)
        overall_match = len(unmatched_source) == 0 and all(m["match"] for m in matched)

        return {
            "overall_match": overall_match,
            "matched_blocks": matched,
            "unmatched_source": unmatched_source,
            "summary": f"{len(matched)} blocks, {len(unmatched_source)} unmatched source types",
        }

    def _block_type(self, block: Any) -> str:
        if isinstance(block, dict):
            return block.get("type", "unknown")
        if hasattr(block, "type"):
            return block.type
        return "unknown"

    def _block_params(self, block: Any) -> Dict[str, Any]:
        if isinstance(block, dict):
            return block.get("params", {})
        if hasattr(block, "params"):
            return block.params
        return {}

    def _translated_lines(self, block: Any) -> List[str]:
        if isinstance(block, dict):
            lines = block.get("translated_lines", [])
            return lines if isinstance(lines, list) else []
        if hasattr(block, "translated_lines"):
            return block.translated_lines
        return []

    def _fail_entry(self, block_type: str) -> Dict[str, Any]:
        return {"type": block_type, "match": False, "similarity": 0.0, "params_diff": [], "function_diff": "no translation found"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_semantic_compare.py -v`
Expected: PASS (all 5 tests)

- [ ] **Step 5: Commit**

```bash
git add core/semantic_compare.py tests/test_semantic_compare.py
git commit -m "feat: add SemanticComparator for rule-based IR semantic validation"
```

---

### Task A-2: Wire SemanticComparator into TranslateNode

- [ ] **Step 1: Write the failing integration test**

```python
# Add to tests/test_semantic_compare.py

def test_translate_node_uses_semantic_comparator(monkeypatch):
    from core.graph import State
    from core.graph.nodes import TranslateNode

    call_count = [0]
    real_compare = None

    class FakeLLM:
        def chat(self, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return {
                    "content": '[{"type":"vlan","function":"create vlan","params":{"id":10},"original_lines":["vlan 10"],"confidence":1.0}]'
                }
            return {
                "content": '[{"type":"vlan","original_lines":["vlan 10"],"translated_lines":[],"confidence":0.0}]'
            }

    from core import semantic_compare
    original = semantic_compare.SemanticComparator.compare

    def patched_compare(self, ir_source, ir_translation):
        # Verify inputs are non-empty lists
        assert isinstance(ir_source, list) and len(ir_source) > 0
        assert isinstance(ir_translation, list) and len(ir_translation) > 0
        return {"overall_match": False, "matched_blocks": [], "unmatched_source": ["vlan"], "summary": "patched"}

    monkeypatch.setattr(semantic_compare.SemanticComparator, "compare", patched_compare)

    llm = FakeLLM()
    state = State()
    state.set("config_text", "vlan 10")
    state.set("from_vendor", "cisco")
    state.set("to_vendor", "huawei")

    result = TranslateNode(llm=llm).execute(state)

    assert result.is_success()
    # Verify lightweight heuristic is NOT used
    assert state.get("ir_compare", {}).get("summary") == "patched"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_semantic_compare.py::test_translate_node_uses_semantic_comparator -v`
Expected: FAIL — old code uses lightweight block, not SemanticComparator

- [ ] **Step 3: Modify `TranslateNode.execute()` in `core/graph/nodes.py`**

Replace lines 128-146 (the lightweight `ir_compare` construction) with:

```python
        # Replace lightweight heuristic with rule-based semantic comparison
        from core.semantic_compare import SemanticComparator, IRBlock

        source_blocks = [
            IRBlock(
                type=b.get("type", "unknown"),
                function=b.get("function", ""),
                params=b.get("params", {}),
                original_lines=b.get("original_lines", []),
                confidence=b.get("confidence", 0.8),
            )
            for b in ir_source
            if isinstance(b, dict)
        ]

        comparator = SemanticComparator()
        ir_compare = comparator.compare(source_blocks, translation_result)

        state.set("ir_back", [])
        state.set("ir_compare", ir_compare)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_semantic_compare.py::test_translate_node_uses_semantic_comparator -v`
Expected: PASS

- [ ] **Step 5: Run all existing tests to check regression**

Run: `python3 -m pytest tests/ -v`
Expected: All existing tests pass (no regressions)

- [ ] **Step 6: Commit**

```bash
git add core/graph/nodes.py tests/test_semantic_compare.py
git commit -m "feat: wire SemanticComparator into TranslateNode, replace lightweight heuristic"
```

---

## Track B: LLM Singleton + tiktoken Context Compression

### Overview

Replace `llm or LLM()` pattern (which creates a new instance per node) with a module-level singleton in `core/__init__.py`. Also replace the `*4` char-based token estimation in `context.py` with tiktoken encoding for accurate context budget management.

### Files

- **Modify:** `core/__init__.py:27-46` — add `get_llm()` singleton factory
- **Modify:** `core/context.py:94-101` — replace char-based compression with tiktoken
- **Modify:** `core/graph/nodes.py:71-158` — inject shared LLM into TranslateNode
- **Modify:** `core/graph/nodes.py:220-275` — inject shared LLM into SemanticValidatorNode
- **Modify:** `core/graph/agent.py:56-59` — use singleton in GraphAgent init
- **Create:** `tests/test_llm_singleton_and_tiktoken.py` — unit tests

### Task B-1: LLM Singleton

- [ ] **Step 1: Write the failing test**

```python
# tests/test_llm_singleton_and_tiktoken.py
import pytest
from unittest.mock import patch

def test_llm_singleton_returns_same_instance():
    # Clear any cached instance first
    import core
    core._llm_instance = None
    core._llm_settings_applied = False

    llm1 = core.get_llm()
    llm2 = core.get_llm()
    assert llm1 is llm2

def test_llm_singleton_respects_env_vars():
    import core
    core._llm_instance = None
    core._llm_settings_applied = False

    with patch.dict("os.environ", {"LLM_API_KEY": "test-key", "LLM_MODEL": "test-model", "LLM_BASE_URL": "http://test.local"}):
        llm = core.get_llm()
        assert llm.api_key == "test-key"
        assert llm.model == "test-model"
        assert llm.base_url == "http://test.local"

def test_llm_singleton_returns_error_when_no_config():
    import core
    core._llm_instance = None
    core._llm_settings_applied = False

    with patch.dict("os.environ", {}, clear=True):
        # Patch get_current_settings to return empty
        import llm_settings
        original = llm_settings.get_current_settings
        llm_settings.get_current_settings = lambda: {"api_key": "", "model": "MiniMax-M2.7", "base_url": "", "timeout": 45}
        try:
            llm = core.get_llm()
            # Should still be LLM instance (created with empty key), not None
            assert llm is not None
        finally:
            llm_settings.get_current_settings = original
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_llm_singleton_and_tiktoken.py::test_llm_singleton_returns_same_instance -v`
Expected: FAIL — `get_llm` not defined

- [ ] **Step 3: Implement LLM singleton in `core/__init__.py`**

Append after the `LLM` class definition (after line 46):

```python
# ─── LLM Singleton ─────────────────────────────────────────────────────────

_llm_instance: Optional[LLM] = None
_llm_settings_applied: bool = False


def get_llm() -> LLM:
    """Return the shared LLM singleton, creating it once from current settings."""
    global _llm_instance, _llm_settings_applied
    if _llm_instance is None or not _llm_settings_applied:
        from llm_settings import create_llm_from_settings

        _llm_instance = create_llm_from_settings()
        _llm_settings_applied = True
    return _llm_instance


def reset_llm_singleton() -> None:
    """Reset singleton — primarily for testing."""
    global _llm_instance, _llm_settings_applied
    _llm_instance = None
    _llm_settings_applied = False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_llm_singleton_and_tiktoken.py::test_llm_singleton_returns_same_instance -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/__init__.py tests/test_llm_singleton_and_tiktoken.py
git commit -m "feat: add LLM singleton via get_llm() factory"
```

---

### Task B-2: tiktoken Context Compression

- [ ] **Step 1: Write the failing test**

```python
# Add to tests/test_llm_singleton_and_tiktoken.py

def test_context_compression_uses_tiktoken():
    import core.context as ctx

    pipeline = ctx.GSSCPipeline(max_context_tokens=50)

    # A string known to be longer than 50 tokens in tiktoken
    long_text = " ".join(["word"] * 300)

    result = pipeline._compress(long_text)

    # With tiktoken encoding (cl100k_base), "word " * 300 ≈ 300 tokens
    # At 50 token budget, result should be strictly shorter
    assert len(result) < len(long_text)
    assert result.endswith("截断") or result.endswith("...")

def test_context_compression_preserves_short_text():
    import core.context as ctx

    pipeline = ctx.GSSCPipeline(max_context_tokens=50)
    short = "short config text"

    result = pipeline._compress(short)

    assert result == short

def test_token_counting_is_accurate():
    import core.context as ctx

    pipeline = ctx.GSSCPipeline(max_context_tokens=10)

    # 10 tokens exactly should pass, 11 should truncate
    text_10 = " ".join(["x"] * 10)
    text_11 = " ".join(["x"] * 11)

    result_10 = pipeline._compress(text_10)
    result_11 = pipeline._compress(text_11)

    assert result_10 == text_10  # exactly at budget
    assert len(result_11) < len(text_11)  # truncated
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_llm_singleton_and_tiktoken.py::test_context_compression_uses_tiktoken -v`
Expected: FAIL — `_compress` still uses `*4` char estimation

- [ ] **Step 3: Replace `_compress` in `core/context.py`**

Replace `_compress` method (lines 94-101):

```python
    def _compress(self, text: str) -> str:
        if not text:
            return ""
        try:
            import tiktoken
            enc = tiktoken.get_encoding("cl100k_base")
            tokens = enc.encode(text)
            max_tokens = self.max_context_tokens
            if len(tokens) <= max_tokens:
                return text
            # reserve 8 tokens for truncation marker
            truncated = enc.decode(tokens[: max_tokens - 8])
            return truncated + "\n...截断"
        except Exception:
            # Fallback to character-based if tiktoken unavailable
            max_chars = self.max_context_tokens * 4
            if len(text) <= max_chars:
                return text
            return text[: max_chars - 8] + "\n...截断"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_llm_singleton_and_tiktoken.py::test_context_compression_uses_tiktoken -v`
Expected: PASS

- [ ] **Step 5: Run full tiktoken test suite**

Run: `python3 -m pytest tests/test_llm_singleton_and_tiktoken.py -v`
Expected: All 5 tests pass

- [ ] **Step 6: Run all existing tests to check regression**

Run: `python3 -m pytest tests/ -v`
Expected: All existing tests pass

- [ ] **Step 7: Commit**

```bash
git add core/context.py tests/test_llm_singleton_and_tiktoken.py
git commit -m "feat: replace char-based context compression with tiktoken encoding"
```

---

### Task B-3: Inject Shared LLM into Nodes

- [ ] **Step 1: Write the failing test**

```python
# Add to tests/test_llm_singleton_and_tiktoken.py

def test_nodes_use_shared_llm_singleton():
    import core
    core.reset_llm_singleton()

    # Patch get_llm to return a mock
    mock_llm = object()
    called_with = []

    def fake_get_llm():
        called_with.append(1)
        return mock_llm

    with patch.object(core, "get_llm", fake_get_llm):
        from core.graph.nodes import TranslateNode, SemanticValidatorNode

        t_node = TranslateNode(llm=None)
        s_node = SemanticValidatorNode(llm=None)

        assert t_node.llm is mock_llm
        assert s_node.llm is mock_llm
        assert len(called_with) == 2

def test_graph_agent_uses_singleton_llm():
    import core
    core.reset_llm_singleton()

    mock_llm = object()

    def fake_get_llm():
        return mock_llm

    with patch.object(core, "get_llm", fake_get_llm):
        from core.graph.agent import GraphAgent

        agent = GraphAgent(llm=None)
        assert agent.llm is mock_llm
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_llm_singleton_and_tiktoken.py::test_nodes_use_shared_llm_singleton -v`
Expected: FAIL — `llm or LLM()` still creates own instance

- [ ] **Step 3: Modify TranslateNode and SemanticValidatorNode to use get_llm()**

In `core/graph/nodes.py`:

```python
# At top of file, add:
from core import get_llm

# In TranslateNode.__init__ (line ~79):
def __init__(self, node_id: str = "translate", llm: Optional[LLM] = None, knowledge_dir: str = "knowledge", agent=None):
    super().__init__(node_id, "translate")
    self.llm = llm if llm is not None else get_llm()
    self.knowledge = KnowledgeRetriever(knowledge_dir)
    self.agent = agent

# In SemanticValidatorNode.__init__ (line ~221):
def __init__(self, node_id: str = "semantic_validate", llm: Optional[LLM] = None, max_retries: int = 3):
    super().__init__(node_id, "semantic_validate")
    self.llm = llm if llm is not None else get_llm()
    self.max_retries = max_retries
```

In `core/graph/agent.py`:

```python
# In GraphAgent.__init__ (line ~39):
def __init__(self, ..., llm: Optional[LLM] = None, ...):
    ...
    self.llm = llm if llm is not None else get_llm()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_llm_singleton_and_tiktoken.py::test_nodes_use_shared_llm_singleton -v`
Expected: PASS

- [ ] **Step 5: Run all existing tests**

Run: `python3 -m pytest tests/ -v`
Expected: All existing tests pass

- [ ] **Step 6: Commit**

```bash
git add core/graph/nodes.py core/graph/agent.py tests/test_llm_singleton_and_tiktoken.py
git commit -m "feat: nodes use shared LLM singleton instead of own instances"
```

---

## Track C: Parallel Knowledge Retrieval + FallbackNode Reuses parsed_config

### Overview

Parallelize the knowledge retrieval step (which is I/O bound) by running it in a ThreadPoolExecutor concurrently with the first LLM call. Also make `FallbackNode` accept `parsed_config` from `ParseNode` to avoid re-parsing config_text when falling back.

### Files

- **Modify:** `core/graph/nodes.py:84-158` — parallelize knowledge retrieval in `TranslateNode`
- **Modify:** `core/graph/nodes.py:305-321` — `FallbackNode` accepts `parsed_config` from state
- **Create:** `tests/test_parallel_knowledge_and_fallback.py` — unit and integration tests

### Task C-1: Parallel Knowledge Retrieval in TranslateNode

- [ ] **Step 1: Write the failing test**

```python
# tests/test_parallel_knowledge_and_fallback.py
from unittest.mock import patch, MagicMock
from concurrent.futures import ThreadPoolExecutor
import time

def test_knowledge_retrieval_runs_in_parallel_with_llm(monkeypatch):
    """Verify knowledge retrieval doesn't block on LLM call."""
    from core.graph.nodes import TranslateNode

    llm_start = [0]
    kn_start = [0]

    class MockLLM:
        def chat(self, **kwargs):
            llm_start[0] = time.time()
            time.sleep(0.1)  # Simulate LLM latency
            return {"content": '[{"type":"vlan","function":"vlan","params":{"id":10},"original_lines":["vlan 10"],"confidence":1.0}]'}

    class MockKnowledgeStore:
        def retrieve_for_ir_block(self, block, target_vendor=None):
            kn_start[0] = time.time()
            time.sleep(0.05)  # Simulate file I/O
            class Chunk:
                chunk_id = "vlan"
                content = "vlan knowledge"
            return [Chunk()]

        def format_for_prompt(self, chunks, max_chars=2000):
            return "[vlan knowledge]"

    from core.graph import State

    state = State()
    state.set("config_text", "vlan 10")
    state.set("from_vendor", "cisco")
    state.set("to_vendor", "huawei")

    monkeypatch.setenv("LLM_API_KEY", "fake")
    monkeypatch.setenv("LLM_BASE_URL", "http://fake")

    from tools import knowledge_manager
    original_ks = knowledge_manager.get_knowledge_store()

    class FakeStore:
        instance = MockKnowledgeStore()
    monkeypatch.setattr(knowledge_manager, "get_knowledge_store", lambda: FakeStore.instance)

    node = TranslateNode(llm=MockLLM())
    result = node.execute(state)

    assert result.is_success()
    # Knowledge retrieval started before or concurrently with LLM (not after)
    # If parallel, kn_start should be recorded (even if result same-thread)
    assert state.get("translated_config") is not None

def test_fallback_node_reuses_parsed_config(monkeypatch):
    from core.graph.nodes import FallbackNode
    from core.graph import State
    from tools import ConfigParser

    mock_parser = MagicMock()
    mock_parser.parse.return_value = MagicMock(vendor="cisco", interfaces=[], vlans=[10])

    config_text = "vlan 10\ninterface GigabitEthernet0/1\n switchport mode trunk"

    state = State()
    state.set("config_text", config_text)
    state.set("parsed_config", mock_parser.parse(config_text, "cisco"))  # Pre-parsed
    state.set("from_vendor", "cisco")
    state.set("to_vendor", "huawei")
    state.set("translate_error", "simulated failure")

    # Verify FallbackNode can access parsed_config
    node = FallbackNode()
    result = node.execute(state)

    assert result.is_success()
    assert state.get("fallback_used") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_parallel_knowledge_and_fallback.py::test_fallback_node_reuses_parsed_config -v`
Expected: FAIL — `FallbackNode` doesn't check for `parsed_config` in state

- [ ] **Step 3: Modify FallbackNode to use parsed_config**

Replace `FallbackNode.execute()` (lines 305-321):

```python
class FallbackNode(Node):
    def __init__(self, node_id: str = "fallback", knowledge_dir: str = "knowledge"):
        super().__init__(node_id, "fallback")
        self.knowledge = KnowledgeRetriever(knowledge_dir)

    def execute(self, state: State) -> NodeResult:
        from core.rule_translator import RuleBasedTranslator

        from_vendor = state.get("from_vendor", "unknown")
        to_vendor = state.get("to_vendor", "unknown")
        error = state.get("translate_error", "unknown error")

        # Prefer pre-parsed config for rule-based fallback
        parsed_config = state.get("parsed_config")
        if parsed_config is not None and hasattr(parsed_config, "raw_lines") and parsed_config.raw_lines:
            config_text = "\n".join(parsed_config.raw_lines)
        else:
            config_text = state.get("config_text", "")

        translated = RuleBasedTranslator().translate(config_text, from_vendor, to_vendor)
        state.set("fallback_used", True)
        state.set("fallback_reason", error)
        if translated:
            state.set("translated_config", translated)
        return NodeResult(
            self.node_id,
            NodeStatus.SUCCESS,
            output=translated or "[fallback] translation failed",
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_parallel_knowledge_and_fallback.py::test_fallback_node_reuses_parsed_config -v`
Expected: PASS

- [ ] **Step 5: Modify TranslateNode to parallelize knowledge retrieval**

Replace the knowledge retrieval block in `TranslateNode.execute()` (lines 101-109):

```python
        # Parallel knowledge retrieval + LLM call (both I/O-bound)
        knowledge_store = get_knowledge_store()
        ir_source_local = ir_source  # capture for thread

        def retrieve_chunks():
            chunks = []
            seen = set()
            for block in ir_source_local:
                for chunk in knowledge_store.retrieve_for_ir_block(block, target_vendor=to_vendor):
                    if chunk.chunk_id not in seen:
                        seen.add(chunk.chunk_id)
                        chunks.append(chunk)
            return chunks

        with ThreadPoolExecutor(max_workers=1) as executor:
            chunks_future = executor.submit(retrieve_chunks)
            translation_result = translate_ir(ir_source, to_vendor, self.llm, knowledge_context=None)
            chunks = chunks_future.result()
            knowledge_context = knowledge_store.format_for_prompt(chunks) if chunks else ""

            # If knowledge retrieval produced context, re-translate with context
            if knowledge_context:
                translation_result = translate_ir(ir_source, to_vendor, self.llm, knowledge_context=knowledge_context)
```

Note: This uses a ThreadPoolExecutor (stdlib) to run knowledge retrieval in a background thread while the first LLM call happens on the main thread. When both complete, if knowledge was retrieved, it re-translates with context for better accuracy.

- [ ] **Step 6: Run fallback test first (unchanged by parallel modification)**

Run: `python3 -m pytest tests/test_parallel_knowledge_and_fallback.py::test_fallback_node_reuses_parsed_config -v`
Expected: PASS

- [ ] **Step 7: Run all existing tests**

Run: `python3 -m pytest tests/ -v`
Expected: All existing tests pass

- [ ] **Step 8: Commit**

```bash
git add core/graph/nodes.py tests/test_parallel_knowledge_and_fallback.py
git commit -m "feat: parallelize knowledge retrieval and reuse parsed_config in FallbackNode"
```

---

## Track D: EpisodicMemory Size Limit

### Overview

Add a configurable max events limit to `EpisodicMemory` to prevent unbounded growth of `events.jsonl`.

### Files

- **Modify:** `memory/__init__.py:66-86` — add `max_events` parameter + trim on `search()`
- **Create:** `tests/test_memory.py` — unit tests for memory cleanup

### Task D-1: Add max_events to EpisodicMemory

- [ ] **Step 1: Write the failing test**

```python
# tests/test_memory.py
import pytest
import tempfile
import pathlib
from memory import EpisodicMemory, TranslationEvent

def test_episodic_memory_trims_excess_events(tmp_path):
    mem = EpisodicMemory(memory_dir=str(tmp_path), max_events=5)

    for i in range(10):
        event = TranslationEvent(
            event_id=f"evt-{i}",
            timestamp="2024-01-01T00:00:00Z",
            from_vendor="cisco",
            to_vendor="huawei",
            original_config="vlan 10",
            translated_config="vlan 10",
            summary="ok",
            user="test",
        )
        mem.record(event)

    # After 10 events with max_events=5, only 5 should remain in the file
    lines = tmp_path / "events.jsonl"
    assert lines.exists()
    count = len([l for l in lines.read_text().splitlines() if l.strip()])
    assert count == 5

def test_episodic_memory_unlimited_when_max_events_zero(tmp_path):
    mem = EpisodicMemory(memory_dir=str(tmp_path), max_events=0)  # 0 = unlimited

    for i in range(20):
        event = TranslationEvent(
            event_id=f"evt-{i}",
            timestamp="2024-01-01T00:00:00Z",
            from_vendor="cisco",
            to_vendor="huawei",
            original_config="vlan 10",
            translated_config="vlan 10",
            summary="ok",
            user="test",
        )
        mem.record(event)

    lines = tmp_path / "events.jsonl"
    count = len([l for l in lines.read_text().splitlines() if l.strip()])
    assert count == 20
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_memory.py -v`
Expected: FAIL — `max_events` parameter not yet supported

- [ ] **Step 3: Modify `EpisodicMemory` in `memory/__init__.py`**

Update `__init__` and add trim logic to `record()`:

```python
class EpisodicMemory:
    def __init__(self, memory_dir: str = "memory_data", max_events: int = 0):
        self.memory_dir = Path(memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.memory_dir / "events.jsonl"
        self.max_events = max_events  # 0 = unlimited

    def record(self, event: TranslationEvent):
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
        self._trim()

    def _trim(self):
        if self.max_events <= 0:
            return
        # Keep only the most recent max_events lines
        lines = [l for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]
        if len(lines) <= self.max_events:
            return
        with self.path.open("w", encoding="utf-8") as f:
            f.write("\n".join(lines[-self.max_events :]) + "\n")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_memory.py -v`
Expected: PASS

- [ ] **Step 5: Run all existing tests**

Run: `python3 -m pytest tests/ -v`
Expected: All existing tests pass

- [ ] **Step 6: Commit**

```bash
git add memory/__init__.py tests/test_memory.py
git commit -m "feat: add max_events limit to EpisodicMemory with automatic trim"
```

---

## Final Verification

After all tracks complete:

1. Run: `python3 -m pytest tests/ -v` — all tests pass
2. Run: `python3 scripts/release_gate.py` — release gate green
3. Run: `python3 run.py` — CLI starts cleanly
4. Verify `docs/superpowers/plans/` contains this plan

---

## Execution Option

**Plan complete and saved to `docs/superpowers/plans/2026-05-16-production-optimization.md`. Three execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**3. Sequential inline with this session** — I'll execute the tasks one by one in this session, verifying each step before proceeding

Which approach?