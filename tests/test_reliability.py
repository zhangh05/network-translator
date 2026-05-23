# -*- coding: utf-8 -*-
"""Tests for LLM retry error classification and urllib fallback."""

from __future__ import annotations

import pytest


class TestIsRetryableError:
    """All HTTP/system errors must be correctly classified as retryable or not."""

    def test_429_is_retryable(self):
        from core import LLM

        assert LLM._is_retryable_error("HTTP 429: rate limit exceeded") is True

    def test_500_is_retryable(self):
        from core import LLM

        assert LLM._is_retryable_error("HTTP 500: internal server error") is True

    def test_502_is_retryable(self):
        from core import LLM

        assert LLM._is_retryable_error("HTTP 502: bad gateway") is True

    def test_503_is_retryable(self):
        from core import LLM

        assert LLM._is_retryable_error("HTTP 503: service unavailable") is True

    def test_timeout_is_retryable(self):
        from core import LLM

        assert LLM._is_retryable_error("timeout reading response") is True
        assert LLM._is_retryable_error("timed out waiting for response") is True

    def test_connection_refused_is_retryable(self):
        from core import LLM

        assert LLM._is_retryable_error("Connection refused") is True
        assert LLM._is_retryable_error("connection reset by peer") is True

    def test_400_is_not_retryable(self):
        from core import LLM

        assert LLM._is_retryable_error("HTTP 400: bad request") is False

    def test_401_is_not_retryable(self):
        from core import LLM

        assert LLM._is_retryable_error("HTTP 401: unauthorized") is False

    def test_403_is_not_retryable(self):
        from core import LLM

        assert LLM._is_retryable_error("HTTP 403: forbidden") is False

    def test_404_is_not_retryable(self):
        from core import LLM

        assert LLM._is_retryable_error("HTTP 404: not found") is False

    def test_auth_failure_not_retryable(self):
        from core import LLM

        assert LLM._is_retryable_error("Invalid API key") is False
        assert LLM._is_retryable_error("Authentication failed") is False


class TestAnthropicUrlNormalization:
    """Minimax anthropic endpoint URL must always end in /v1/messages."""

    def test_strips_trailing_slash_and_appends_v1_messages(self):
        from core import LLM

        llm = LLM()
        result = llm._anthropic_url_from("https://api.minimaxi.com/anthropic")
        assert result == "https://api.minimaxi.com/anthropic/v1/messages"

    def test_no_change_when_already_has_v1_messages(self):
        from core import LLM

        llm = LLM()
        result = llm._anthropic_url_from("https://api.minimaxi.com/anthropic/v1/messages")
        assert result == "https://api.minimaxi.com/anthropic/v1/messages"

    def test_v1_suffix_gets_messages(self):
        from core import LLM

        llm = LLM()
        result = llm._anthropic_url_from("https://api.minimaxi.com/anthropic/v1")
        assert result == "https://api.minimaxi.com/anthropic/v1/messages"


class TestProviderFallbackRetry:
    """ProviderFallback basic behavior tests."""

    def test_execute_calls_fn_with_provider(self):
        from core.provider_fallback import ProviderFallback, ProviderConfig

        cfg = ProviderConfig(api_key="k", base_url="http://x", model="m")
        pf = ProviderFallback([cfg])
        called = []
        result = pf.execute(lambda p: (called.append(p.base_url) or {"ok": True}))
        assert called == ["http://x"]
        assert result == {"ok": True}

    def test_execute_returns_last_error_when_all_fail(self):
        from core.provider_fallback import ProviderFallback, ProviderConfig

        cfg = ProviderConfig(api_key="k", base_url="http://x", model="m")
        pf = ProviderFallback([cfg])
        result = pf.execute(lambda p: {"error": "fail", "content": ""})
        assert result == {"error": "fail", "content": ""}