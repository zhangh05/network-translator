# -*- coding: utf-8 -*-
"""LLM settings loader with external file support.

Priority (highest to lowest):
    1. LLM_SETTINGS_FILE env var — explicit path provided at runtime
    2. External LLM settings file (see EXTERNAL_SETTINGS_PATH below)
    3. Project-local llmsetting.json  (llm_settings.py sibling)
    4. Environment variable fallbacks (LLM_API_KEY / LLM_MODEL / LLM_BASE_URL / LLM_TIMEOUT)
       — always honored as ultimate fallback when no file provides the value

The external settings file is intended for developer-machine-local secrets
(e.g. /Users/zhangh01/Desktop/codex_net_trans/llm_settings.txt) and is NOT committed
to source control.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from core import LLM
from core.runtime_config import get_int_setting, write_private_json

logger = logging.getLogger("translator.llm_settings")

DEFAULT_BASE_URL = "https://api.minimaxi.com/anthropic"
DEFAULT_MODEL = "MiniMax-M2.7"
DEFAULT_TIMEOUT = 45
MAX_TIMEOUT = 300

# Path to the external developer-machine-local settings file.
# This file should NOT be committed to source control.
EXTERNAL_SETTINGS_PATH = Path("/Users/zhangh01/Desktop/codex_net_trans/llm_settings.txt")


def mask_api_key(key: str | None) -> str:
    """Return a safe display string for an API key.

    Shows only '***' to prevent any accidental key leakage in logs.
    """
    if not key:
        return "(not set)"
    return "***"


def mask_api_key_safe(key: str | None) -> str:
    """Alias for mask_api_key — never shows key content."""
    return mask_api_key(key)


def _settings_file() -> Path | None:
    """Return the project-local settings file path, or None if it doesn't exist."""
    override = os.environ.get("LLM_SETTINGS_FILE", "").strip()
    if override:
        return Path(override).expanduser()
    local = Path(__file__).resolve().parent / "llmsetting.json"
    return local if local.exists() else None


def _read_external_settings() -> dict:
    """Read the external settings file if it exists and is parseable.

    The file should contain JSON with fields:
      - api_url  (mapped to base_url internally)
      - api_key
      - model

    Returns an empty dict if the file is absent or malformed.
    All errors are logged at WARNING level with sanitized messages only.
    """
    path = EXTERNAL_SETTINGS_PATH
    if not path.exists():
        return {}
    try:
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            logger.warning("External settings file is empty: %s", path)
            return {}
        data = json.loads(raw)
        if not isinstance(data, dict):
            logger.warning("External settings file is not a JSON object: %s", path)
            return {}
        result = {}
        # api_url -> base_url
        api_url = data.get("api_url") or data.get("api-url")
        if api_url and isinstance(api_url, str):
            result["base_url"] = api_url.strip()
        # api_key — stored as-is (caller must never log it)
        api_key = data.get("api_key") or data.get("api-key")
        if api_key and isinstance(api_key, str):
            result["api_key"] = api_key
        # model with normalization (strip whitespace, case-insensitive)
        model = data.get("model")
        if model and isinstance(model, str):
            result["model"] = model.strip()
        timeout = data.get("timeout")
        if timeout is not None:
            result["timeout"] = _coerce_timeout(timeout)
        return result
    except json.JSONDecodeError:
        logger.warning("External settings file is not valid JSON: %s", path)
        return {}
    except OSError:
        logger.warning("Cannot read external settings file: %s", path)
        return {}


def _coerce_timeout(value, default: int = DEFAULT_TIMEOUT) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if parsed < 1:
        return 1
    if parsed > MAX_TIMEOUT:
        return MAX_TIMEOUT
    return parsed


def get_current_settings() -> dict:
    local = _read_local_settings()
    local_timeout = _coerce_timeout(local.get("timeout", DEFAULT_TIMEOUT))
    return {
        "api_key": os.environ.get("LLM_API_KEY") or local.get("api_key", ""),
        "model": os.environ.get("LLM_MODEL") or local.get("model", DEFAULT_MODEL),
        "base_url": os.environ.get("LLM_BASE_URL") or local.get("base_url", DEFAULT_BASE_URL),
        "timeout": get_int_setting("LLM_TIMEOUT", local_timeout, minimum=1, maximum=MAX_TIMEOUT),
    }


def save_settings(data: dict) -> None:
    current = _read_local_settings()
    api_key = data.get("api_key", "")
    if api_key == "***":
        api_key = current.get("api_key", "")
    payload = {
        "api_key": api_key,
        "model": (data.get("model") or DEFAULT_MODEL).strip(),
        "base_url": (data.get("base_url") or DEFAULT_BASE_URL).strip(),
        "timeout": _coerce_timeout(data.get("timeout", DEFAULT_TIMEOUT)),
    }
    write_private_json(_settings_file(), payload)
    # Reset cached agent so next request uses new settings
    try:
        from project_store import reset_translation_agent
        reset_translation_agent()
    except Exception:
        logger.warning("Failed to reset translation agent after settings save", exc_info=True)


def _read_local_settings() -> dict:
    """Read settings from external file, then project-local file.

    Priority:
        1. External settings file (EXTERNAL_SETTINGS_PATH)
        2. Project-local llmsetting.json
        3. Empty dict (env vars will be merged in get_current_settings)
    """
    # Priority 1: external file
    ext = _read_external_settings()
    if ext:
        return ext
    # Priority 2: project-local file
    settings_file = Path(__file__).resolve().parent / "llmsetting.json"
    if not settings_file.exists():
        return {}
    try:
        return json.loads(settings_file.read_text(encoding="utf-8"))
    except Exception:
        logger.warning("Failed to read llmsetting.json")
        return {}


def create_llm_from_settings() -> LLM:
    cfg = get_current_settings()
    api_key = cfg["api_key"]
    model = cfg["model"]
    base_url = cfg["base_url"]
    timeout = cfg["timeout"]
    return LLM(api_key=api_key, model=model, base_url=base_url, timeout=timeout)


def register_llm_routes(app) -> None:
    from flask import request, abort

    def _auth():
        import os
        secret = os.environ.get("API_SECRET", "")
        if not secret:
            return
        token = request.headers.get("X-API-Secret", "")
        if token != secret:
            abort(401, "unauthorized")

    @app.route("/api/llm/settings", methods=["GET"])
    def llm_settings_get():
        _auth()
        settings = get_current_settings()
        if settings.get("api_key"):
            settings["api_key"] = "***"
        return {"ok": True, "settings": settings}

    @app.route("/api/llm/settings", methods=["PUT"])
    def llm_settings_put():
        _auth()
        data = request.get_json() or {}
        save_settings(data)
        return {"ok": True}

    @app.route("/api/llm/test", methods=["POST"])
    def llm_settings_test():
        _auth()
        cfg = get_current_settings()
        if not cfg.get("api_key"):
            return {"ok": False, "error": "未配置 API Key，请先在设置中填写"}, 400
        llm = create_llm_from_settings()
        result = llm.chat(
            messages=[{"role": "user", "content": "Reply with OK and nothing else."}],
            temperature=0,
            max_tokens=16,
        )
        if result.get("error"):
            logger.warning("LLM connectivity test failed: %s", result["error"])
            return {"ok": False, "error": result["error"]}, 502
        content = (result.get("content") or "").strip().rstrip('.!?')
        if not content:
            # LLM API reached but returned empty — try another prompt
            result2 = llm.chat(
                messages=[{"role": "user", "content": "Hello"}],
                temperature=0.3,
                max_tokens=32,
            )
            if result2.get("error"):
                logger.warning("LLM test retry failed: %s", result2["error"])
                return {"ok": False, "error": result2["error"]}, 502
            content = (result2.get("content") or "").strip()
            if not content:
                return {"ok": False, "error": "LLM 返回内容为空"}, 502
        return {"ok": True, "content": content[:50]}
