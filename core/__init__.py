# -*- coding: utf-8 -*-
"""Core primitives and lightweight LLM adapter."""

from __future__ import annotations

import json
import logging
import os
import random
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("translator.core")


class Role(str, Enum):
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"
    TOOL = "tool"


@dataclass
class Message:
    role: Role
    content: str
    tool_name: Optional[str] = None


class LLM:
    """Small chat wrapper.

    If no API key is configured, return an error payload so graph fallback can trigger.
    """

    def __init__(
        self,
        api_key: str = "",
        model: str = "MiniMax-M2.7",
        base_url: Optional[str] = None,
        timeout: int = 45,
        max_retries: int = 2,
    ):
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
        self.model = model or os.environ.get("LLM_MODEL", "MiniMax-M2.7")
        self.base_url = base_url or os.environ.get("LLM_BASE_URL", "").strip()
        self.timeout = timeout
        self.max_retries = max_retries

    def _retry_post(self, fn, *args, **kwargs):
        last_err = ""
        for attempt in range(self.max_retries + 1):
            try:
                result = fn(*args, **kwargs)
                if isinstance(result, dict) and result.get("error"):
                    last_err = result["error"]
                    if attempt < self.max_retries and self._is_retryable_error(last_err):
                        time.sleep(0.5 * (2 ** attempt) + random.uniform(0, 0.3))
                        continue
                    return result
                return result
            except Exception as exc:
                last_err = str(exc)
                if attempt < self.max_retries:
                    time.sleep(0.5 * (2 ** attempt) + random.uniform(0, 0.3))
                    continue
                return {"error": last_err, "content": ""}
        return {"error": last_err, "content": ""}

    @staticmethod
    def _is_retryable_error(err: str) -> bool:
        err_lower = err.lower()
        if "429" in err or "too many requests" in err_lower:
            return True
        if "500" in err or "502" in err or "503" in err:
            return True
        if "timeout" in err_lower or "timed out" in err_lower:
            return True
        if "connection" in err_lower and ("refused" in err_lower or "reset" in err_lower):
            return True
        return False

    def chat(
        self,
        messages: List[Dict[str, str]],
        system: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        if not self.api_key:
            return {"error": "LLM API key missing", "content": ""}

        # Compatible no-network default: caller can still fall back.
        if not self.base_url:
            return {"error": "LLM base URL missing", "content": ""}

        if self._is_anthropic_endpoint():
            return self._chat_anthropic(
                messages=messages,
                system=system,
                temperature=temperature,
                max_tokens=max_tokens,
            )

        payload_messages: List[Dict[str, str]] = []
        if system:
            payload_messages.append({"role": "system", "content": system})
        payload_messages.extend(messages or [])

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": payload_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            data = self._post_json(payload, headers)
        except Exception as exc:
            return {"error": str(exc), "content": ""}

        if isinstance(data, dict) and data.get("error"):
            return {"error": data.get("error", "LLM request failed"), "content": ""}

        # Try common response shapes.
        if isinstance(data, dict):
            if "choices" in data and data["choices"]:
                msg = data["choices"][0].get("message", {})
                content = msg.get("content", "") or ""
                tool_calls = msg.get("tool_calls", []) or []
                mapped = []
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    args = fn.get("arguments", {})
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except Exception:
                            args = {}
                    mapped.append({"id": tc.get("id", ""), "name": fn.get("name", ""), "input": args})
                return {"content": content, "tool_calls": mapped}
            if "content" in data:
                return {"content": data.get("content", ""), "tool_calls": data.get("tool_calls", []) or []}

        return {"error": "unrecognized LLM response", "content": ""}

    def _is_anthropic_endpoint(self) -> bool:
        base = self.base_url.rstrip("/").lower()
        return "api.anthropic.com" in base or "/anthropic" in base

    def _anthropic_url(self) -> str:
        base = self.base_url.rstrip("/")
        if base.endswith("/v1/messages"):
            return base
        if base.endswith("/v1"):
            return base + "/messages"
        return base + "/v1/messages"

    def _chat_anthropic(
        self,
        messages: List[Dict[str, str]],
        system: Optional[str],
        temperature: float,
        max_tokens: int,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages or [],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if system:
            payload["system"] = system

        headers = {
            "X-Api-Key": self.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }

        target_url = self._anthropic_url()
        try:
            data = self._post_json_at(payload, headers, target_url, prefer_urllib=True)
        except Exception as exc:
            return {"error": str(exc), "content": ""}

        if isinstance(data, dict) and data.get("error"):
            return {"error": data.get("error", "LLM request failed"), "content": ""}
        if not isinstance(data, dict):
            return {"error": "unrecognized Anthropic response", "content": ""}

        content = data.get("content", "")
        if isinstance(content, list):
            text_parts = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    text_parts.append(part.get("text", ""))
            return {"content": "\n".join(x for x in text_parts if x), "tool_calls": []}
        if isinstance(content, str):
            return {"content": content, "tool_calls": []}
        return {"error": "empty Anthropic response", "content": ""}

    def _post_json(
        self,
        payload: Dict[str, Any],
        headers: Dict[str, str],
        prefer_urllib: bool = False,
    ) -> Dict[str, Any]:
        return self._post_json_at(payload, headers, self.base_url, prefer_urllib)

    def _post_json_at(
        self,
        payload: Dict[str, Any],
        headers: Dict[str, str],
        url: str,
        prefer_urllib: bool = False,
    ) -> Dict[str, Any]:
        if prefer_urllib:
            return self._post_json_urllib(payload, headers, url)
        for attempt in range(self.max_retries + 1):
            try:
                import requests

                resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
                if resp.status_code >= 400:
                    err = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    if attempt < self.max_retries and self._is_retryable_error(err):
                        time.sleep(0.5 * (2 ** attempt) + random.uniform(0, 0.3))
                        continue
                    return {"error": err, "content": ""}
                return resp.json()
            except ImportError:
                return self._post_json_urllib(payload, headers, url)
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                if attempt < self.max_retries:
                    time.sleep(0.5 * (2 ** attempt) + random.uniform(0, 0.3))
                    continue
                return {"error": str(exc)[:300], "content": ""}
        return {"error": "max retries exceeded", "content": ""}

    def _post_json_urllib(self, payload: Dict[str, Any], headers: Dict[str, str], url: Optional[str] = None) -> Dict[str, Any]:
        target = url or self.base_url
        body = json.dumps(payload).encode("utf-8")
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(target, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode("utf-8")
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return {"error": f"invalid JSON response: {raw[:200]}", "content": ""}
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="ignore")
                err = f"HTTP {exc.code}: {raw[:200]}"
                if attempt < self.max_retries and self._is_retryable_error(str(exc.code)):
                    time.sleep(0.5 * (2 ** attempt) + random.uniform(0, 0.3))
                    continue
                return {"error": err, "content": ""}
            except Exception as exc:
                if attempt < self.max_retries and self._is_retryable_error(str(exc)):
                    time.sleep(0.5 * (2 ** attempt) + random.uniform(0, 0.3))
                    continue
                return {"error": str(exc)[:300], "content": ""}
        return {"error": "max retries exceeded", "content": ""}


# ─── LLM Singleton ─────────────────────────────────────────────────────────

_llm_lock = threading.Lock()
_llm_instance: Optional[LLM] = None
_llm_settings_applied: bool = False


def get_llm() -> LLM:
    """Return the shared LLM singleton, creating it once from current settings."""
    global _llm_instance, _llm_settings_applied
    if _llm_instance is None or not _llm_settings_applied:
        from llm_settings import create_llm_from_settings

        with _llm_lock:
            if _llm_instance is None or not _llm_settings_applied:
                try:
                    _llm_instance = create_llm_from_settings()
                    _llm_settings_applied = True
                except Exception:
                    _llm_settings_applied = False
                    logger.exception("Failed to create LLM singleton")
                    raise
    return _llm_instance


def reset_llm_singleton() -> None:
    """Reset singleton — primarily for testing."""
    global _llm_instance, _llm_settings_applied
    _llm_instance = None
    _llm_settings_applied = False
