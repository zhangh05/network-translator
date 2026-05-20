# -*- coding: utf-8 -*-
"""
Provider fallback and circuit breaker for LLM API calls.

Provides:
- ProviderConfig: connection parameters for a single LLM provider
- CircuitBreaker: per-provider failure tracking with auto-recovery
- ProviderFallback: orchestrates multiple providers with health-aware routing

Usage:
    from core.provider_fallback import ProviderFallback, ProviderConfig

    fallback = ProviderFallback([
        ProviderConfig(api_key="key1", base_url="https://primary/api"),
        ProviderConfig(api_key="key2", base_url="https://fallback/api"),
    ])
    result = fallback.execute(lambda provider: llm._post_json(payload, headers))
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("translator.provider_fallback")


@dataclass
class ProviderConfig:
    """Connection parameters for a single LLM provider."""

    api_key: str = ""
    base_url: str = ""
    model: str = ""
    timeout: int = 45
    max_retries: int = 2
    weight: int = 100  # Higher = preferred when all are healthy

    @classmethod
    def from_env(cls, prefix: str = "LLM") -> ProviderConfig:
        """Build from env vars like LLM_API_KEY, LLM_BASE_URL, LLM_MODEL."""
        return cls(
            api_key=os.environ.get(f"{prefix}_API_KEY", ""),
            base_url=os.environ.get(f"{prefix}_BASE_URL", "").strip(),
            model=os.environ.get(f"{prefix}_MODEL", ""),
            timeout=int(os.environ.get(f"{prefix}_TIMEOUT", "45")),
        )

    @classmethod
    def from_env_with_fallback(
        cls, primary_prefix: str = "LLM", fallback_prefix: str = "LLM_FALLBACK"
    ) -> List[ProviderConfig]:
        """Build primary + optional fallback from env vars."""
        configs = [cls.from_env(primary_prefix)]
        fb = cls.from_env(fallback_prefix)
        if fb.base_url and fb.api_key:
            configs.append(fb)
        return configs


@dataclass
class CircuitBreakerState:
    """Per-provider circuit breaker state."""

    failures: int = 0
    last_failure_time: float = 0.0
    state: str = "closed"  # closed → open → half-open → closed
    failure_threshold: int = 3
    cooldown_seconds: float = 60.0
    total_failures: int = 0
    total_successes: int = 0

    @property
    def label(self) -> str:
        if self.state == "closed":
            return "CLOSED"
        elif self.state == "open":
            remaining = max(0, self.cooldown_seconds - (time.time() - self.last_failure_time))
            return f"OPEN({remaining:.0f}s)"
        else:
            return "HALF-OPEN"

    def record_failure(self) -> None:
        self.failures += 1
        self.total_failures += 1
        self.last_failure_time = time.time()
        if self.failures >= self.failure_threshold:
            old_state = self.state
            self.state = "open"
            if old_state != "open":
                logger.warning("Circuit breaker OPEN after %d failures", self.failures)

    def record_success(self) -> None:
        self.failures = 0
        self.total_successes += 1
        if self.state != "closed":
            old_state = self.state
            self.state = "closed"
            logger.info("Circuit breaker CLOSED after success (was %s)", old_state)

    def can_try(self) -> bool:
        if self.state == "closed":
            return True
        if self.state == "open":
            elapsed = time.time() - self.last_failure_time
            if elapsed >= self.cooldown_seconds:
                logger.info("Circuit breaker HALF-OPEN after %.0fs cooldown", elapsed)
                self.state = "half-open"
                return True
            return False
        return True  # half-open


class ProviderFallback:
    """Orchestrates multiple providers with circuit breakers.

    Thread-safe: uses a lock around circuit breaker state mutations.
    """

    def __init__(self, providers: List[ProviderConfig]):
        if not providers:
            raise ValueError("At least one provider required")
        self.providers = providers
        self._circuit_breakers: Dict[int, CircuitBreakerState] = {
            id(p): CircuitBreakerState() for p in providers
        }
        self._lock = threading.Lock()

    def get_state(self, provider: ProviderConfig) -> CircuitBreakerState:
        return self._circuit_breakers[id(provider)]

    def healthy_providers(self) -> List[ProviderConfig]:
        """Return providers sorted by health (closed first, then by weight)."""
        healthy = []
        with self._lock:
            for p in self.providers:
                cb = self._circuit_breakers[id(p)]
                if cb.can_try():
                    healthy.append(p)
        healthy.sort(key=lambda p: (
            0 if self._circuit_breakers[id(p)].state == "closed" else 1,
            -p.weight,
        ))
        return healthy

    def execute(self, fn: Callable[[ProviderConfig], Dict[str, Any]]) -> Dict[str, Any]:
        """Execute `fn(provider)` across providers with fallback.

        Tries healthy providers in order. If all fail, returns last error.
        """
        candidates = self.healthy_providers()
        last_error = {"error": "no healthy providers", "content": ""}

        for provider in candidates:
            cb = self._circuit_breakers[id(provider)]
            try:
                result = fn(provider)
            except Exception as exc:
                err_str = str(exc)
                logger.warning("Provider %s raised: %s", provider.base_url, err_str[:100])
                with self._lock:
                    cb.record_failure()
                last_error = {"error": err_str, "content": ""}
                continue

            if isinstance(result, dict) and result.get("error"):
                err_str = result["error"]
                logger.warning("Provider %s error: %s", provider.base_url, err_str[:100])
                with self._lock:
                    cb.record_failure()
                last_error = result
                continue

            with self._lock:
                cb.record_success()
            return result

        return last_error

    def summary(self) -> List[Dict[str, Any]]:
        """Return provider health summary for observability."""
        with self._lock:
            return [
                {
                    "base_url": p.base_url,
                    "model": p.model,
                    "state": self._circuit_breakers[id(p)].label,
                    "total_failures": self._circuit_breakers[id(p)].total_failures,
                    "total_successes": self._circuit_breakers[id(p)].total_successes,
                    "consecutive_failures": self._circuit_breakers[id(p)].failures,
                }
                for p in self.providers
            ]
