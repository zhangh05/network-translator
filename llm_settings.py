# -*- coding: utf-8 -*-
"""LLM settings loader."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from core import LLM

logger = logging.getLogger("translator.llm_settings")


def get_current_settings() -> dict:
    local = _read_local_settings()
    return {
        "api_key": os.environ.get("LLM_API_KEY") or local.get("api_key", ""),
        "model": os.environ.get("LLM_MODEL") or local.get("model", "MiniMax-M2.7"),
        "base_url": os.environ.get("LLM_BASE_URL") or local.get("base_url", ""),
        "timeout": int(os.environ.get("LLM_TIMEOUT", local.get("timeout", 45))),
    }


def save_settings(data: dict) -> None:
    settings_file = Path(__file__).resolve().parent / "llmsetting.json"
    current = _read_local_settings()
    api_key = data.get("api_key", "")
    if api_key == "***":
        api_key = current.get("api_key", "")
    payload = {
        "api_key": api_key,
        "model": data.get("model", "MiniMax-M2.7"),
        "base_url": data.get("base_url", ""),
        "timeout": int(data.get("timeout", 45)),
    }
    settings_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    # Reset cached agent so next request uses new settings
    try:
        from project_store import reset_translation_agent
        reset_translation_agent()
    except Exception:
        logger.warning("Failed to reset translation agent after settings save", exc_info=True)


def _read_local_settings() -> dict:
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
