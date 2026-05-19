# -*- coding: utf-8 -*-
"""Memory subsystem: working, episodic, semantic."""

from __future__ import annotations

import fcntl
import json
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class TranslationEvent:
    event_id: str
    timestamp: str
    from_vendor: str
    to_vendor: str
    original_config: str
    translated_config: str
    summary: str
    user: str = "anonymous"


@dataclass
class SemanticChunk:
    chunk_id: str
    content: str
    score: float = 0.0


class WorkingMemory:
    def __init__(self, max_size: int = 30, ttl_seconds: int = 7200):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._store: Dict[str, Tuple[Any, float]] = {}

    def _cleanup(self):
        now = time.time()
        expired = [k for k, (_, ts) in self._store.items() if now - ts > self.ttl_seconds]
        for k in expired:
            self._store.pop(k, None)
        # trim oldest
        if len(self._store) > self.max_size:
            ordered = sorted(self._store.items(), key=lambda x: x[1][1])
            for k, _ in ordered[: len(self._store) - self.max_size]:
                self._store.pop(k, None)

    def set(self, key: str, value: Any):
        self._store[key] = (value, time.time())
        self._cleanup()

    def get(self, key: str, default: Any = None) -> Any:
        self._cleanup()
        item = self._store.get(key)
        return default if item is None else item[0]

    def all(self) -> List[Tuple[str, Any]]:
        self._cleanup()
        return [(k, v[0]) for k, v in self._store.items()]


class EpisodicMemory:
    def __init__(self, memory_dir: str = "memory_data", max_events: int = 0):
        self.memory_dir = Path(memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.memory_dir / "events.jsonl"
        self.max_events = max_events

    def record(self, event: TranslationEvent):
        with self.path.open("a", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        if self.max_events > 0:
            self._trim()

    def _trim(self):
        if not self.path.exists():
            return
        # Use locking to prevent concurrent trim corruption
        with self.path.open("r+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                lines = [l for l in f.read().splitlines() if l.strip()]
                if len(lines) <= self.max_events:
                    return
                trimmed = lines[-self.max_events :]
                f.seek(0)
                f.truncate()
                f.write("\n".join(trimmed) + "\n")
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def _load(self) -> List[TranslationEvent]:
        if not self.path.exists():
            return []
        out: List[TranslationEvent] = []
        with self.path.open("r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                        out.append(TranslationEvent(**row))
                    except Exception:
                        continue
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return out

    def search(
        self,
        query: Optional[str] = None,
        from_vendor: Optional[str] = None,
        to_vendor: Optional[str] = None,
        limit: int = 10,
    ) -> List[TranslationEvent]:
        events = self._load()
        results: List[TranslationEvent] = []
        q = (query or "").lower().strip()
        for ev in reversed(events):
            if from_vendor and ev.from_vendor != from_vendor:
                continue
            if to_vendor and ev.to_vendor != to_vendor:
                continue
            if q:
                hay = f"{ev.summary}\n{ev.original_config}\n{ev.translated_config}".lower()
                if q not in hay:
                    continue
            results.append(ev)
            if len(results) >= limit:
                break
        return results


class SemanticMemory:
    def __init__(self, knowledge_dir: str = "knowledge_data"):
        self.knowledge_dir = Path(knowledge_dir)

    def _iter_text_files(self) -> List[Path]:
        files: List[Path] = []
        if self.knowledge_dir.exists():
            files.extend(self.knowledge_dir.rglob("*.md"))
            files.extend(self.knowledge_dir.rglob("*.txt"))
            files.extend(self.knowledge_dir.rglob("*.json"))
        return files

    def retrieve(self, query: str, top_k: int = 3) -> List[SemanticChunk]:
        q = (query or "").lower().strip()
        if not q:
            return []
        chunks: List[SemanticChunk] = []
        for path in self._iter_text_files()[:80]:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if not text.strip():
                continue
            # naive lexical score
            score = 0.0
            for token in q.split():
                if token and token in text.lower():
                    score += 1.0
            if score > 0:
                chunks.append(
                    SemanticChunk(
                        chunk_id=f"{path.name}-{uuid.uuid4().hex[:6]}",
                        content=text[:1200],
                        score=score,
                    )
                )
        chunks.sort(key=lambda x: x.score, reverse=True)
        return chunks[:top_k]

