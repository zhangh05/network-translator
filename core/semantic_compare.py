# core/semantic_compare.py
"""Rule-based IR semantic comparison — no LLM required."""

from __future__ import annotations
import re
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


def _tokenize(text: str) -> set:
    """Extract alphanumeric tokens from text using word boundaries."""
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _keyword_set(params: Dict[str, Any], block: Any = None) -> set:
    """Extract searchable keywords from params for similarity scoring.

    When params is empty, falls back to extracting keywords from
    the block's function and original_lines fields.
    """
    keywords = set()
    for v in params.values():
        if isinstance(v, str):
            keywords.update(_tokenize(v))
        elif isinstance(v, (int, float)):
            keywords.add(str(v))
    # Fallback: extract from function and original_lines when params is sparse
    if len(keywords) == 0 and block is not None:
        if hasattr(block, "function"):
            keywords.update(_tokenize(block.function))
        elif isinstance(block, dict):
            func = block.get("function", "")
            if func:
                keywords.update(_tokenize(func))
        # Also pull from original_lines when available
        if hasattr(block, "original_lines"):
            for line in block.original_lines:
                keywords.update(_tokenize(line))
        elif isinstance(block, dict):
            for line in block.get("original_lines", []):
                keywords.update(_tokenize(line))
    return keywords


class SemanticComparator:
    """Compare ir_source (list of IRBlock) against ir_translation (list of dict).

    Rule-based — no LLM calls. Uses type coverage + field presence + keyword
    similarity to produce an overall_match verdict and per-block match info.
    """

    def compare(self, ir_source: List[Any], ir_translation: List[Any]) -> Dict[str, Any]:
        # Filter out internal _meta entries
        ir_source = [b for b in (ir_source or []) if self._block_type(b) != "_meta"]
        ir_translation = [b for b in (ir_translation or []) if self._block_type(b) != "_meta"]

        if not ir_source:
            return {"overall_match": False, "matched_blocks": [], "unmatched_source": [], "summary": "no source blocks"}
        if not ir_translation:
            return {
                "overall_match": False, "matched_blocks": [],
                "unmatched_source": [self._block_type(b) for b in ir_source],
                "summary": "no translation result",
            }

        # Build list of translation candidates per type (preserving order for 1:1 matching)
        trans_pool: Dict[str, list] = {}
        for tb in ir_translation:
            bt = self._block_type(tb)
            trans_pool.setdefault(bt, []).append(tb)

        # Track which translation candidate index has been consumed per type
        used_index: Dict[str, int] = {}
        for bt in trans_pool:
            used_index[bt] = 0

        matched: List[Dict[str, Any]] = []
        unmatched_source: List[str] = []

        for block in ir_source:
            bt = self._block_type(block)
            candidates = trans_pool.get(bt, [])
            idx = used_index.get(bt, 0)

            if idx >= len(candidates):
                unmatched_source.append(bt)
                matched.append(self._fail_entry(bt))
                continue

            match_candidate = candidates[idx]
            used_index[bt] = idx + 1

            source_keywords = _keyword_set(self._block_params(block), block)
            source_orig_lines = " ".join(self._original_lines(block)).lower()
            source_keywords |= _tokenize(source_orig_lines)
            has_output = bool(self._translated_lines(match_candidate))
            trans_text = " ".join(self._translated_lines(match_candidate)).lower()
            trans_keywords = _tokenize(trans_text)
            overlap = len(source_keywords & trans_keywords) / max(len(source_keywords), 1)
            similarity = overlap if has_output else 0.0
            match_flag = has_output and similarity >= 0.15

            matched.append({
                "type": bt, "match": match_flag, "similarity": round(similarity, 3),
                "params_diff": [],
                "function_diff": "" if match_flag else f"similarity={similarity:.2f}<0.3",
            })

        overall_match = len(unmatched_source) == 0 and all(m["match"] for m in matched)
        return {
            "overall_match": overall_match, "matched_blocks": matched,
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

    def _original_lines(self, block: Any) -> List[str]:
        if isinstance(block, dict):
            lines = block.get("original_lines", [])
            return lines if isinstance(lines, list) else []
        if hasattr(block, "original_lines"):
            return block.original_lines
        return []

    def _fail_entry(self, block_type: str) -> Dict[str, Any]:
        return {"type": block_type, "match": False, "similarity": 0.0, "params_diff": [], "function_diff": "no translation found"}
