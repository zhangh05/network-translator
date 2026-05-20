"""Tests for provider fallback and circuit breaker."""

import time
from unittest.mock import patch

from core.provider_fallback import CircuitBreakerState, ProviderConfig, ProviderFallback


# ── CircuitBreakerState ──

def test_circuit_breaker_starts_closed():
    cb = CircuitBreakerState()
    assert cb.state == "closed"
    assert cb.can_try() is True


def test_circuit_breaker_opens_after_threshold():
    cb = CircuitBreakerState(failure_threshold=2)
    cb.record_failure()
    assert cb.can_try() is True
    assert cb.state == "closed"
    cb.record_failure()
    assert cb.state == "open"
    assert cb.can_try() is False


def test_circuit_breaker_half_open_after_cooldown():
    cb = CircuitBreakerState(failure_threshold=1, cooldown_seconds=999)
    cb.record_failure()
    assert cb.can_try() is False
    cb.last_failure_time = time.time() - 1000
    assert cb.can_try() is True
    assert cb.state == "half-open"


def test_circuit_breaker_closes_on_success():
    cb = CircuitBreakerState(failure_threshold=2)
    cb.record_failure()
    cb.record_failure()
    assert cb.state == "open"
    cb.record_success()
    assert cb.state == "closed"
    assert cb.failures == 0


def test_circuit_breaker_counts():
    cb = CircuitBreakerState(failure_threshold=3)
    cb.record_failure()
    cb.record_failure()
    assert cb.total_failures == 2
    assert cb.total_successes == 0
    cb.record_success()
    assert cb.total_successes == 1


# ── ProviderConfig ──

def test_provider_config_from_env(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://test/api")
    monkeypatch.setenv("LLM_MODEL", "test-model")

    pc = ProviderConfig.from_env()
    assert pc.api_key == "test-key"
    assert pc.base_url == "https://test/api"
    assert pc.model == "test-model"


def test_provider_config_from_env_without_fallback(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "primary-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://primary/api")
    monkeypatch.delenv("LLM_FALLBACK_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_FALLBACK_API_KEY", raising=False)

    configs = ProviderConfig.from_env_with_fallback()
    assert len(configs) == 1


def test_provider_config_from_env_with_fallback(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "primary-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://primary/api")
    monkeypatch.setenv("LLM_FALLBACK_API_KEY", "fallback-key")
    monkeypatch.setenv("LLM_FALLBACK_BASE_URL", "https://fallback/api")

    configs = ProviderConfig.from_env_with_fallback()
    assert len(configs) == 2
    assert configs[0].api_key == "primary-key"
    assert configs[1].api_key == "fallback-key"
    assert configs[1].base_url == "https://fallback/api"


# ── ProviderFallback ──

def test_fallback_requires_at_least_one_provider():
    try:
        ProviderFallback([])
        assert False, "Should have raised"
    except ValueError:
        pass


def test_fallback_uses_single_provider():
    fb = ProviderFallback([ProviderConfig(api_key="k", base_url="https://test/api")])
    result = fb.execute(lambda p: {"content": "ok"})
    assert result == {"content": "ok"}


def test_fallback_tries_second_provider_after_first_fails():
    fb = ProviderFallback([
        ProviderConfig(api_key="fail", base_url="https://fail/api"),
        ProviderConfig(api_key="ok", base_url="https://ok/api"),
    ])
    call_order = []

    def fn(p):
        call_order.append(p.api_key)
        if p.api_key == "fail":
            return {"error": "timeout"}
        return {"content": "ok"}

    result = fb.execute(fn)
    assert result == {"content": "ok"}
    assert call_order == ["fail", "ok"]


def test_fallback_tracks_failures():
    fb = ProviderFallback([
        ProviderConfig(api_key="p1", base_url="https://p1/api"),
        ProviderConfig(api_key="p2", base_url="https://p2/api"),
    ])

    def fail(p):
        return {"error": "timeout"}

    result = fb.execute(fail)
    assert "error" in result

    summary = fb.summary()
    assert summary[0]["consecutive_failures"] == 1
    assert summary[1]["consecutive_failures"] == 1


def test_fallback_circuit_breaker_opens_and_skips():
    """After enough failures, the failed provider should be skipped."""
    fb = ProviderFallback([
        ProviderConfig(api_key="p1", base_url="https://p1/api"),
        ProviderConfig(api_key="p2", base_url="https://p2/api"),
    ])
    # Set low failure threshold
    for cb in fb._circuit_breakers.values():
        cb.failure_threshold = 2

    def alternating(p):
        if p.api_key == "p1":
            return {"error": "timeout"}
        return {"error": "also down"}

    # First two calls: both fail
    fb.execute(alternating)
    fb.execute(alternating)
    fb.execute(alternating)  # p1 should be open now, only p2 tried

    summary = fb.summary()
    assert summary[0]["state"].startswith("OPEN")


def test_fallback_recovers_after_success():
    fb = ProviderFallback([
        ProviderConfig(api_key="p1", base_url="https://p1/api"),
    ])
    cb = fb._circuit_breakers[id(fb.providers[0])]
    cb.failure_threshold = 1

    # Open the circuit
    fb.execute(lambda p: {"error": "timeout"})
    assert cb.state == "open"

    # Force half-open (skip cooldown)
    cb.last_failure_time = time.time() - 999
    cb.state = "half-open"

    # Succeed
    fb.execute(lambda p: {"content": "recovered"})
    assert cb.state == "closed"
    assert cb.total_successes == 1


def test_healthy_providers_sorted_by_state_then_weight():
    fb = ProviderFallback([
        ProviderConfig(api_key="heavy", base_url="https://heavy/api", weight=200),
        ProviderConfig(api_key="light", base_url="https://light/api", weight=50),
    ])
    # Make the heavy one unhealthy
    cb_heavy = fb._circuit_breakers[id(fb.providers[0])]
    cb_heavy.failure_threshold = 1
    cb_heavy.record_failure()

    healthy = fb.healthy_providers()
    assert len(healthy) == 1
    assert healthy[0].api_key == "light"


# ── Integration: LLM with fallback providers ──

def test_llm_uses_fallback_when_primary_fails():
    from core import LLM
    llm = LLM(
        fallback_providers=[
            ProviderConfig(api_key="primary-key", base_url="https://primary/api"),
            ProviderConfig(api_key="fb-key", base_url="https://fallback/api"),
        ],
    )
    assert llm._fallback is not None
    assert len(llm._fallback.providers) == 2


def test_llm_without_fallback_has_no_fallback():
    from core import LLM
    llm = LLM(api_key="k", base_url="https://test/api")
    assert llm._fallback is None
