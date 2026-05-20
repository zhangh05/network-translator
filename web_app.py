# -*- coding: utf-8 -*-
"""
网络配置翻译助手 - Web 界面 (Graph Architecture)
Flask 后端 + 静态 HTML 前端
"""

import atexit
import hashlib
import json
import logging
import os
import sys
import threading
import time
import uuid
from pathlib import Path
from datetime import datetime, timezone

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("translator")

# ── JSONL Translation Log ──
LOG_DIR = project_root / "logs"
LOG_DIR.mkdir(exist_ok=True)
TRANSLATION_LOG = LOG_DIR / "translation.jsonl"

_log_lock = threading.Lock()


def _write_log(entry: dict):
    """Append one JSON line to translation log (thread-safe)."""
    try:
        with _log_lock:
            with open(TRANSLATION_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
                f.flush()
    except Exception:
        logger.exception("Failed to write translation log")


# ── Version ──
def _read_version() -> str:
    try:
        return (project_root / "VERSION").read_text().strip()
    except Exception:
        return "unknown"


VERSION = _read_version()


def _get_model_name() -> str:
    name = os.environ.get("LLM_MODEL")
    if name:
        return name
    if os.environ.get("LLM_API_KEY"):
        return "configured"
    return "rule-based"


def _get_analyzer_count() -> int:
    try:
        from core.analyzers import AnalyzerRegistry
        r = AnalyzerRegistry()
        return len(r.get_registered_features())
    except Exception:
        return 0


def _get_feature_count() -> int:
    try:
        import yaml
        reg = yaml.safe_load((project_root / "knowledge_data" / "features" / "registry.yaml").read_text())
        features = reg.get("features", {}) if isinstance(reg, dict) else {}
        return len(features)
    except Exception:
        return 0


# ── API ──
import llm_settings
import project_store

ALLOWED_VENDORS = {"huawei", "h3c", "cisco", "ruijie", "hillstone", "topsec", "dptech"}
API_SECRET = os.environ.get("API_SECRET", "")


def _strip_markdown_fence(text: str) -> str:
    import re
    text = re.sub(r'^```\w*\n', '', text)
    text = re.sub(r'\n```\s*$', '', text)
    return text.strip()


def _require_auth():
    from flask import request, abort
    if not API_SECRET:
        return
    token = request.headers.get("X-API-Secret") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if token != API_SECRET:
        abort(401, "unauthorized")


def create_app():
    from flask import Flask, request, send_from_directory, make_response, jsonify, abort

    app = Flask(__name__, static_folder='frontend', static_url_path='')
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB max body
    app.logger = logger

    @app.after_request
    def _add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        response.headers["Access-Control-Allow-Origin"] = request.origin if request.origin else "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Secret, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    llm_settings.register_llm_routes(app)
    project_store.register_project_routes(app)

    @app.route("/api/domain/meta", methods=["GET"])
    def domain_meta():
        from core.domain import ALL_DOMAINS, ALL_VENDORS, DOMAIN_VENDORS, VENDOR_PLATFORMS, get_all_features
        return {
            "ok": True,
            "domains": ALL_DOMAINS,
            "vendors": ALL_VENDORS,
            "domain_vendors": {d: vs for d, vs in DOMAIN_VENDORS.items()},
            "platforms": {v: ps for v, ps in VENDOR_PLATFORMS.items()},
            "features": list(get_all_features().keys()),
        }

    @app.route("/")
    def index():
        resp = make_response(app.send_static_file("index.html"))
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    @app.route("/healthz", methods=["GET"])
    def healthz():
        return {"ok": True, "status": "healthy"}

    @app.route("/readyz", methods=["GET"])
    def readyz():
        issues = []
        warnings = []
        if not (project_root / "VERSION").exists():
            issues.append("VERSION missing")
        if not (project_root / "knowledge_data").is_dir():
            issues.append("knowledge_data missing")
        if not os.environ.get("LLM_API_KEY"):
            warnings.append("LLM_API_KEY not set — falling back to rule-based translation")
        if not (project_root / "memory_data").is_dir():
            warnings.append("memory_data directory missing")
        try:
            _get_analyzer_count()
        except Exception:
            warnings.append("analyzers not loadable")
        status = "ready"
        if issues:
            status = "not_ready"
            return {"ok": False, "status": status, "issues": issues, "warnings": warnings}, 503
        return {"ok": True, "status": status, "version": VERSION, "model": _get_model_name(), "warnings": warnings}

    @app.route("/api/version", methods=["GET"])
    def version():
        return {
            "ok": True,
            "version": VERSION,
            "model": _get_model_name(),
            "analyzers": _get_analyzer_count(),
            "features": _get_feature_count(),
            "python": sys.version.split()[0],
        }

    @app.route("/api/translate", methods=["POST"])
    def translate_once():
        _require_auth()
        request_id = str(uuid.uuid4())
        t0 = time.time()

        data = request.get_json() or {}
        config_text = (data.get("config_text") or "").strip()
        from_vendor = (data.get("from_vendor") or "auto").strip().lower()
        to_vendor = (data.get("to_vendor") or "huawei").strip().lower()
        source_domain = (data.get("source_domain") or "").strip().lower()
        source_platform = (data.get("source_platform") or "").strip().lower()
        target_domain = (data.get("target_domain") or "").strip().lower()
        target_platform = (data.get("target_platform") or "").strip().lower()

        if not config_text:
            return {"ok": False, "error": "No config provided", "error_code": "EMPTY_CONFIG",
                    "request_id": request_id, "version": VERSION}, 400
        if from_vendor != "auto" and from_vendor not in ALLOWED_VENDORS:
            return {"ok": False, "error": "Unsupported source vendor", "error_code": "UNSUPPORTED_SOURCE",
                    "request_id": request_id, "version": VERSION}, 400
        if to_vendor not in ALLOWED_VENDORS:
            return {"ok": False, "error": "Unsupported target vendor", "error_code": "UNSUPPORTED_TARGET",
                    "request_id": request_id, "version": VERSION}, 400

        try:
            result = project_store.run_translation(
                config_text=config_text,
                from_vendor=from_vendor,
                to_vendor=to_vendor,
                source_domain=source_domain,
                source_platform=source_platform,
                target_domain=target_domain,
                target_platform=target_platform,
                user="api_user",
            )
            if isinstance(result, dict):
                translated = result.get("translated", "")
                if "```" in translated:
                    cleaned = _strip_markdown_fence(translated)
                    result["translated"] = cleaned

            elapsed = time.time() - t0
            log_entry = _build_log_entry(
                request_id, elapsed, config_text,
                from_vendor, to_vendor, source_domain, source_platform,
                target_domain, target_platform, result, error=None,
            )
            _write_log(log_entry)

            return {
                "ok": True,
                "request_id": request_id,
                "version": VERSION,
                "model": _get_model_name(),
                "result": result,
            }
        except Exception as e:
            elapsed = time.time() - t0
            logger.exception("Translation failed [%s]", request_id)
            log_entry = _build_log_entry(
                request_id, elapsed, config_text,
                from_vendor, to_vendor, source_domain, source_platform,
                target_domain, target_platform, result=None, error=str(e),
            )
            _write_log(log_entry)
            return {
                "ok": False,
                "request_id": request_id,
                "version": VERSION,
                "error": "Internal translation error",
                "error_code": "TRANSLATION_INTERNAL_ERROR",
            }, 500

    return app


def _build_log_entry(
    request_id, elapsed, config_text,
    from_vendor, to_vendor, source_domain, source_platform,
    target_domain, target_platform, result, error,
):
    config_hash = "sha256:" + hashlib.sha256(config_text.encode()).hexdigest()[:16]
    config_snippet = config_text[:120].replace("\n", "\\n")

    entry = {
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "version": VERSION,
        "model": _get_model_name(),
        "elapsed_ms": round(elapsed * 1000),
        "source_domain": source_domain or "",
        "source_vendor": from_vendor,
        "source_platform": source_platform or "",
        "target_domain": target_domain or "",
        "target_vendor": to_vendor,
        "target_platform": target_platform or "",
        "config_hash": config_hash,
        "config_snippet": config_snippet,
    }

    if error:
        entry["success"] = False
        entry["error_reason"] = error[:500]
        return entry

    entry["success"] = result.get("success", False)
    entry["cache_hit"] = result.get("cache_hit", False)
    entry["fallback_used"] = result.get("fallback_used", False)
    entry["route_decision"] = result.get("route_decision", "unknown")
    entry["features"] = result.get("features", [])
    entry["risk_signals"] = result.get("risk_signals", [])
    entry["node_results"] = result.get("node_results", [])
    entry["capability_gaps"] = result.get("capability_gaps", [])
    entry["analyzer_results"] = result.get("analyzer_results", [])

    ar = result.get("analyzer_results", [])
    warning_count = 0
    fatal_count = 0
    if isinstance(ar, list):
        for a in ar:
            risk = a.get("risk_level", "") if isinstance(a, dict) else ""
            if risk == "fatal":
                fatal_count += 1
            elif risk == "warning":
                warning_count += 1
    entry["analyzer_warning_count"] = warning_count
    entry["analyzer_fatal_count"] = fatal_count

    val = result.get("validation", {})
    if isinstance(val, dict):
        entry["validation_level"] = val.get("level", "info")
        entry["deployable"] = val.get("deployable", True)
        entry["manual_review_required"] = val.get("manual_review_required", False)
        entry["warning_count"] = len(val.get("warnings", []))
        entry["error_count"] = len(val.get("errors", []))
    else:
        entry["validation_level"] = "info"
        entry["deployable"] = True
        entry["manual_review_required"] = False

    return entry


app = create_app()


@atexit.register
def _cleanup():
    from tools.knowledge_manager import clear_knowledge_cache
    clear_knowledge_cache()
    logger.info("Knowledge cache cleared on shutdown")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(host="127.0.0.1", port=port, debug=debug)
