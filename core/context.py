# -*- coding: utf-8 -*-
"""GSSC context pipeline (gather/select/structure/compress)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, List, Sequence

_encoder = None

def _get_encoder():
    global _encoder
    if _encoder is None:
        import tiktoken
        _encoder = tiktoken.get_encoding("cl100k_base")
    return _encoder


@dataclass
class ContextItem:
    source: str
    text: str
    score: float = 0.0


class GSSCPipeline:
    def __init__(self, max_context_tokens: int = 3000):
        self.max_context_tokens = max_context_tokens

    @staticmethod
    def _normalize_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        return str(value).strip()

    def _gather(
        self,
        working_memory_items: Sequence[Any] | None = None,
        episodic_events: Sequence[Any] | None = None,
        semantic_chunks: Sequence[Any] | None = None,
        recent_tool_results: Sequence[Any] | None = None,
        knowledge_context: str = "",
        session_meta: dict | None = None,
    ) -> List[ContextItem]:
        items: List[ContextItem] = []

        for pair in working_memory_items or []:
            if isinstance(pair, tuple) and len(pair) >= 2:
                items.append(ContextItem("session", f"{pair[0]}: {self._normalize_text(pair[1])}", 0.8))

        for e in episodic_events or []:
            txt = getattr(e, "summary", "") or getattr(e, "translated_config", "") or str(e)
            items.append(ContextItem("history", self._normalize_text(txt), 0.7))

        for c in semantic_chunks or []:
            txt = getattr(c, "content", "") or getattr(c, "text", "") or str(c)
            items.append(ContextItem("knowledge", self._normalize_text(txt), 0.9))

        for r in recent_tool_results or []:
            items.append(ContextItem("tool", self._normalize_text(r), 0.75))

        if knowledge_context:
            items.append(ContextItem("knowledge", knowledge_context.strip(), 0.95))

        if session_meta:
            items.append(ContextItem("meta", self._normalize_text(session_meta), 1.0))

        return [x for x in items if x.text]

    @staticmethod
    def _select(query: str, items: Iterable[ContextItem], top_k: int = 20) -> List[ContextItem]:
        q = (query or "").lower()
        scored = []
        for item in items:
            hit = 0.0
            if q:
                for token in q.split():
                    if token and token in item.text.lower():
                        hit += 0.1
            scored.append((item.score + hit, item))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in scored[:top_k]]

    @staticmethod
    def _structure(items: Sequence[ContextItem]) -> str:
        buckets = {"meta": [], "session": [], "history": [], "knowledge": [], "tool": []}
        for item in items:
            buckets.setdefault(item.source, []).append(item.text)

        lines: List[str] = []
        for key in ("meta", "session", "history", "knowledge", "tool"):
            vals = buckets.get(key, [])
            if not vals:
                continue
            lines.append(f"[{key}]")
            lines.extend(f"- {v}" for v in vals[:8])
            lines.append("")
        return "\n".join(lines).strip()

    def _compress(self, text: str) -> str:
        if not text:
            return ""
        try:
            enc = _get_encoder()
            tokens = enc.encode(text)
            max_tokens = self.max_context_tokens
            if len(tokens) <= max_tokens:
                return text
            # reserve 3 tokens for truncation marker "\n..."
            truncated = enc.decode(tokens[: max_tokens - 3])
            return truncated + "\n..."
        except Exception:
            # Fallback to whitespace token counting if tiktoken unavailable.
            parts = text.split()
            if len(parts) <= self.max_context_tokens:
                return text
            keep = max(self.max_context_tokens - 3, 1)
            return " ".join(parts[:keep]) + "\n..."

    def build(
        self,
        query: str,
        working_memory_items: Sequence[Any] | None = None,
        episodic_events: Sequence[Any] | None = None,
        semantic_chunks: Sequence[Any] | None = None,
        recent_tool_results: Sequence[Any] | None = None,
        knowledge_context: str = "",
        session_meta: dict | None = None,
    ) -> str:
        gathered = self._gather(
            working_memory_items=working_memory_items,
            episodic_events=episodic_events,
            semantic_chunks=semantic_chunks,
            recent_tool_results=recent_tool_results,
            knowledge_context=knowledge_context,
            session_meta=session_meta,
        )
        selected = self._select(query=query, items=gathered)
        structured = self._structure(selected)
        return self._compress(structured)
