# -*- coding: utf-8 -*-
"""
Project Store - 项目管理
每个项目独立上下文，支持多项目并行操作
"""

import fcntl
import json
import logging
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

logger = logging.getLogger("translator.project_store")

PROJECT_DIR = Path(__file__).parent / "projects"

# ── Sensitive output redaction ─────────────────────────────────────────────
# Applied before any user-facing output leaves the service (API response,
# project persistence, copy/export). Ensures LLM success path and fallback
# path produce equally clean output.

_REDACT_PATTERNS = [
    (re.compile(r'(password\s+(?:\d\s+)?)(?!(?:cipher|irreversible-cipher)\s)\S+', re.IGNORECASE), r'\1<redacted>'),
    (re.compile(r'(secret\s+(?:\d\s+)?)\S+', re.IGNORECASE), r'\1<redacted>'),
    (re.compile(r'(cipher\s+)\S+', re.IGNORECASE), r'\1<redacted>'),
    (re.compile(r'(irreversible-cipher\s+)\S+', re.IGNORECASE), r'\1<redacted>'),
    (re.compile(r'(shared-key\s+)(?!(?:cipher|irreversible-cipher)\s)\S+', re.IGNORECASE), r'\1<redacted>'),
    (re.compile(r'(pre-shared-key\s+)(?!(?:cipher|irreversible-cipher)\s)\S+', re.IGNORECASE), r'\1<redacted>'),
    (re.compile(r'(snmp-server\s+community\s+)\S+', re.IGNORECASE), r'\1<redacted>'),
    (re.compile(r'(snmp-agent\s+community\s+\w+\s+cipher\s+)\S+', re.IGNORECASE), r'\1<redacted>'),
    (re.compile(r'(tacacs-server\s+key\s+)\S+', re.IGNORECASE), r'\1<redacted>'),
    (re.compile(r'(radius-server\s+(?:shared-)?key\s+)(?!(?:cipher|irreversible-cipher)\s)\S+', re.IGNORECASE), r'\1<redacted>'),
    (re.compile(r'(radius\s+shared-key\s+)(?!(?:cipher|irreversible-cipher)\s)\S+', re.IGNORECASE), r'\1<redacted>'),
    (re.compile(r'(neighbor\s+\S+\s+password\s+)\S+', re.IGNORECASE), r'\1<redacted>'),
    (re.compile(r'(set\s+community\s+)\S+', re.IGNORECASE), r'\1<redacted>'),
    (re.compile(r'(apply\s+community\s+)\S+', re.IGNORECASE), r'\1<redacted>'),
]


def redact_sensitive_output(value):
    """Recursively redact sensitive values from any output structure.

    Handles str, list, dict, and nested combinations. Non-text types
    (None, bool, int, float) pass through unchanged.
    """
    if isinstance(value, str):
        for pattern, replacement in _REDACT_PATTERNS:
            value = pattern.sub(replacement, value)
        return value
    if isinstance(value, list):
        return [redact_sensitive_output(item) for item in value]
    if isinstance(value, dict):
        return {k: redact_sensitive_output(v) for k, v in value.items()}
    return value


class Project:
    """项目"""

    def __init__(self, project_id: str, name: str):
        self.id = project_id
        self.name = name
        self.created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.config_text = ""
        self.from_vendor = "auto"
        self.to_vendor = "huawei"
        self.source_domain = ""
        self.source_platform = ""
        self.target_domain = ""
        self.target_platform = ""
        self.result = None
        self.request_id = ""
        self.version = ""
        self.model = ""
        self.history = []
        self.last_translate_hash = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "config_text": self.config_text,
            "from_vendor": self.from_vendor,
            "to_vendor": self.to_vendor,
            "source_domain": self.source_domain,
            "source_platform": self.source_platform,
            "target_domain": self.target_domain,
            "target_platform": self.target_platform,
            "result": self.result,
            "request_id": self.request_id,
            "version": self.version,
            "model": self.model,
            "history_count": len(self.history),
            "last_translate_hash": self.last_translate_hash,
        }

    def to_full_dict(self) -> dict:
        d = self.to_dict()
        d["history"] = self.history[:20]  # 最近20条 (newest first, so take first 20)
        return d


class ProjectStore:
    """项目存储"""

    _INDEX_TTL = 30.0  # 内存索引超过此秒数自动从磁盘重载

    def __init__(self, project_dir: str = None):
        self.project_dir = Path(project_dir) if project_dir else PROJECT_DIR
        self.project_dir.mkdir(exist_ok=True)
        self.meta_file = self.project_dir / "projects.json"
        self._projects: Dict[str, Project] = {}
        self._last_load: float = 0.0
        self._index_mtime_ns: Optional[int] = None
        self._load_index()

    def _ensure_fresh(self):
        current_mtime = self._index_mtime()
        if current_mtime != self._index_mtime_ns or time.time() - self._last_load > self._INDEX_TTL:
            self._load_index()

    def _index_mtime(self) -> Optional[int]:
        try:
            return self.meta_file.stat().st_mtime_ns
        except FileNotFoundError:
            return None

    @staticmethod
    def _locked_write(filepath: Path, write_fn):
        """Write atomically with an exclusive sidecar lock."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        lockfile = filepath.with_suffix(filepath.suffix + ".lock")
        tmpfile = filepath.with_suffix(filepath.suffix + f".{os.getpid()}.{threading.get_ident()}.tmp")
        with open(lockfile, "a", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                with open(tmpfile, "w", encoding="utf-8") as f:
                    write_fn(f)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmpfile, filepath)
            finally:
                try:
                    if tmpfile.exists():
                        tmpfile.unlink()
                except OSError:
                    pass
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _locked_read(filepath: Path) -> Optional[dict]:
        """Read with the same sidecar lock used by atomic writes."""
        if not filepath.exists():
            return None
        lockfile = filepath.with_suffix(filepath.suffix + ".lock")
        with open(lockfile, "a", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    return json.load(f)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _project_from_data(project_id: str, data: Dict[str, Any]) -> Project:
        """Build a Project from persisted index/detail data."""
        proj = Project(project_id, data.get("name", ""))
        proj.created_at = data.get("created_at", proj.created_at)
        proj.updated_at = data.get("updated_at", proj.created_at)
        proj.config_text = data.get("config_text", "")
        proj.from_vendor = data.get("from_vendor", "auto")
        proj.to_vendor = data.get("to_vendor", "huawei")
        proj.source_domain = data.get("source_domain", "")
        proj.source_platform = data.get("source_platform", "")
        proj.target_domain = data.get("target_domain", "")
        proj.target_platform = data.get("target_platform", "")
        proj.result = data.get("result")
        proj.request_id = data.get("request_id") or ""
        proj.version = data.get("version") or ""
        proj.model = data.get("model") or ""
        proj.history = data.get("history", [])
        proj.last_translate_hash = data.get("last_translate_hash") or ""
        return proj

    def _load_index(self):
        """加载项目索引，并对历史数据进行hydration回填。"""
        self._projects.clear()
        try:
            data = self._locked_read(self.meta_file)
        except Exception:
            logger.exception("Failed to load project index; recovering from detail files")
            data = None
        if data:
            for p in data.get("projects", []):
                proj = self._project_from_data(p["id"], p)

                # Backfill: hydrate missing result and metadata from detail file
                # for historical projects that predate the request_id/version/model fields.
                detail_file = self._get_project_file(proj.id)
                if detail_file.exists():
                    try:
                        detail_data = self._locked_read(detail_file)
                        if detail_data:
                            # Result: backfill only if index result is None but detail has it
                            if proj.result is None and detail_data.get("result") is not None:
                                proj.result = detail_data.get("result")
                            # Metadata: backfill None or empty fields from detail
                            for field in ("request_id", "version", "model"):
                                idx_val = getattr(proj, field, None) or ""
                                detail_val = detail_data.get(field)
                                if not idx_val and detail_val:
                                    setattr(proj, field, detail_val)
                    except Exception:
                        pass

                self._projects[p["id"]] = proj

        # Recovery: projects.json is an index, not the durable source of truth.
        # If it is stale/truncated/corrupt, recover orphan detail files so refresh
        # and later saves do not hide or drop existing projects.
        for detail_file in self.project_dir.glob("*.json"):
            if detail_file.name == self.meta_file.name:
                continue
            project_id = detail_file.stem
            if project_id in self._projects:
                continue
            try:
                detail_data = self._locked_read(detail_file)
                if detail_data:
                    self._projects[project_id] = self._project_from_data(project_id, detail_data)
            except Exception:
                logger.exception("Failed to recover project detail %s", project_id)
        self._last_load = time.time()
        self._index_mtime_ns = self._index_mtime()

    def _save_index(self):
        """保存项目索引"""
        try:
            data = {"projects": [p.to_dict() for p in self._projects.values()]}
            self._locked_write(self.meta_file, lambda f: json.dump(data, f, indent=2, ensure_ascii=False))
            self._index_mtime_ns = self._index_mtime()
        except Exception:
            logger.exception("Failed to save project index")

    def _get_project_file(self, project_id: str) -> Path:
        if not re.match(r'^[a-zA-Z0-9_-]+$', project_id):
            raise ValueError(f"Invalid project_id: {project_id!r}")
        return self.project_dir / f"{project_id}.json"

    def create_project(self, name: str = None) -> Project:
        self._ensure_fresh()
        """创建新项目"""
        project_id = str(uuid.uuid4())[:8]
        project_name = name or f"项目 {len(self._projects) + 1}"
        project = Project(project_id, project_name)
        self._projects[project_id] = project
        self._save_project(project)
        self._save_index()
        return project

    def get_project(self, project_id: str, reload: bool = False) -> Optional[Project]:
        """获取项目（优先使用内存缓存，只在缓存不存在时从detail文件加载）。"""
        self._ensure_fresh()
        if reload:
            filepath = self._get_project_file(project_id)
            try:
                data = self._locked_read(filepath)
                if data:
                    proj = self._project_from_data(project_id, data)
                    self._projects[project_id] = proj
                    return proj
            except Exception:
                logger.exception("Failed to read project %s", project_id)
            return None
        if project_id in self._projects:
            return self._projects[project_id]
        filepath = self._get_project_file(project_id)
        try:
            data = self._locked_read(filepath)
            if data:
                proj = self._project_from_data(project_id, data)
                self._projects[project_id] = proj
                return proj
        except Exception:
            logger.exception("Failed to read project %s", project_id)
        return None

    def _save_project(self, project: Project):
        """保存项目数据"""
        try:
            filepath = self._get_project_file(project.id)
            self._locked_write(filepath, lambda f: json.dump(project.to_full_dict(), f, indent=2, ensure_ascii=False))
        except Exception:
            logger.exception("Failed to save project %s", project.id)

    def update_project(self, project_id: str, updates: Dict) -> bool:
        """更新项目"""
        project = self.get_project(project_id)
        if not project:
            return False

        if "name" in updates:
            project.name = updates["name"]
        if "config_text" in updates:
            project.config_text = updates["config_text"]
        if "from_vendor" in updates:
            project.from_vendor = updates["from_vendor"]
        if "to_vendor" in updates:
            project.to_vendor = updates["to_vendor"]
        if "source_domain" in updates:
            project.source_domain = updates["source_domain"]
        if "source_platform" in updates:
            project.source_platform = updates["source_platform"]
        if "target_domain" in updates:
            project.target_domain = updates["target_domain"]
        if "target_platform" in updates:
            project.target_platform = updates["target_platform"]
        if "result" in updates:
            project.result = redact_sensitive_output(updates["result"])
        if "request_id" in updates:
            project.request_id = updates["request_id"]
        if "version" in updates:
            project.version = updates["version"]
        if "model" in updates:
            project.model = updates["model"]
        if "last_translate_hash" in updates:
            project.last_translate_hash = updates["last_translate_hash"]

        project.updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self._save_project(project)
        self._save_index()
        return True

    def add_history(self, project_id: str, entry: Dict):
        """添加历史记录"""
        project = self.get_project(project_id)
        if not project:
            return False

        history_entry = {
            "config_snippet": entry.get("config_text", "")[:100],
            "from_vendor": entry.get("from_vendor"),
            "to_vendor": entry.get("to_vendor"),
            "source_domain": entry.get("source_domain", ""),
            "source_platform": entry.get("source_platform", ""),
            "target_domain": entry.get("target_domain", ""),
            "target_platform": entry.get("target_platform", ""),
            "success": entry.get("success", False),
            "translated_snippet": entry.get("translated", "")[:100] if entry.get("translated") else "",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        project.history.insert(0, history_entry)
        project.history = project.history[:50]  # 保留最近50条
        self._save_project(project)
        return True

    def list_projects(self) -> List[Dict]:
        """列出所有项目（摘要）"""
        self._ensure_fresh()
        return [p.to_dict() for p in self._projects.values()]

    def delete_project(self, project_id: str) -> bool:
        """删除项目"""
        self._ensure_fresh()
        filepath = self._get_project_file(project_id)
        if project_id in self._projects or filepath.exists():
            self._projects.pop(project_id, None)
            if filepath.exists():
                filepath.unlink()
            self._save_index()
            return True
        return False


# 全局单例
_project_store: Optional[ProjectStore] = None


def get_project_store() -> ProjectStore:
    global _project_store
    if _project_store is None:
        _project_store = ProjectStore()
    return _project_store


def run_translation(
    config_text: str,
    from_vendor: str,
    to_vendor: str,
    user: str = "anonymous",
    source_domain: str = "",
    source_platform: str = "",
    target_domain: str = "",
    target_platform: str = "",
) -> Dict[str, Any]:
    """Run translation with a consistent result schema for all API routes."""
    agent = _get_translation_agent()

    result = agent.run(
        config_text=config_text,
        from_vendor=from_vendor,
        to_vendor=to_vendor,
        user=user,
        source_domain=source_domain,
        source_platform=source_platform,
        target_domain=target_domain,
        target_platform=target_platform,
    )
    return {
        "translated": result.get("translated", ""),
        "validation": result.get("validation", {}),
        "semantic_validation": result.get("semantic_validation", {}),
        "diff": result.get("diff", ""),
        "node_results": result.get("node_results", []),
        "success": result.get("success", False),
        "fallback_used": result.get("fallback_used", False),
        "fallback_reason": result.get("fallback_reason", ""),
        "route_decision": result.get("route_decision", "unknown"),
        "cache_hit": result.get("cache_hit", False),
        "capability_gaps": result.get("capability_gaps", []),
        "capability_gap_severity": result.get("capability_gap_severity", "info"),
        "capability_notes": result.get("capability_notes", []),
        "source_domain": result.get("source_domain", ""),
        "source_platform": result.get("source_platform", ""),
        "target_domain": result.get("target_domain", ""),
        "target_platform": result.get("target_platform", ""),
        "features": result.get("features", []),
        "module_summary": result.get("module_summary", {}),
        "module_graph": result.get("module_graph", {}),
        "analyzer_results": result.get("analyzer_results", []),
        "risk_signals": result.get("risk_signals", []),
        "deployable_config": result.get("deployable_config", ""),
        "manual_review_config": result.get("manual_review_config", ""),
        "module_translations": result.get("module_translations", {}),
        "module_translation_coverage": result.get("module_translation_coverage", {}),
    }


_agent_instance = None
_agent_lock = threading.Lock()


def _get_translation_agent():
    """Lazy singleton: reuse GraphAgent across requests."""
    global _agent_instance
    if _agent_instance is None:
        with _agent_lock:
            if _agent_instance is None:
                _agent_instance = _create_agent()
    return _agent_instance


def reset_translation_agent():
    """Reset cached agent so next request picks up new settings."""
    global _agent_instance
    _agent_instance = None


def _create_agent():
    from core.graph.agent import GraphAgent
    from llm_settings import create_llm_from_settings

    return GraphAgent(
        knowledge_dir=str(Path(__file__).parent / "knowledge_data"),
        memory_dir=str(Path(__file__).parent / "memory_data"),
        llm=create_llm_from_settings(),
    )


def _read_version() -> str:
    try:
        return (Path(__file__).parent / "VERSION").read_text().strip()
    except Exception:
        return "unknown"


def _get_model_name() -> str:
    return os.environ.get("LLM_MODEL", "MiniMax-M2.7")


def _write_translation_log(
    request_id, elapsed, config_text,
    from_vendor, to_vendor, source_domain, source_platform,
    target_domain, target_platform, result, error,
):
    """Write a JSONL log entry (lazy-import from web_app to avoid circular import)."""
    try:
        from web_app import _build_log_entry, _write_log
        entry = _build_log_entry(
            request_id, elapsed, config_text,
            from_vendor, to_vendor, source_domain, source_platform,
            target_domain, target_platform, result, error,
        )
        _write_log(entry)
    except Exception:
        logger.exception("Failed to write translation log for %s", request_id)


def register_project_routes(app):
    """注册项目相关路由"""
    from flask import request, abort

    def _auth():
        import os
        secret = os.environ.get("API_SECRET", "")
        if not secret:
            return
        token = request.headers.get("X-API-Secret", "")
        if token != secret:
            abort(401, "unauthorized")

    @app.route("/api/projects", methods=["GET"])
    def list_projects():
        """列出所有项目"""
        _auth()
        store = get_project_store()
        projects = store.list_projects()
        for p in projects:
            if p.get("result") is not None:
                p["result"] = redact_sensitive_output(p["result"])
        return {"ok": True, "projects": projects}

    @app.route("/api/projects", methods=["POST"])
    def create_project():
        """创建新项目"""
        _auth()
        data = request.get_json() or {}
        store = get_project_store()
        name = (data.get("name") or "").strip()[:200]
        project = store.create_project(name)
        return {"ok": True, "project": project.to_dict()}

    @app.route("/api/projects/<project_id>", methods=["GET"])
    def get_project(project_id):
        """获取项目详情"""
        _auth()
        store = get_project_store()
        project = store.get_project(project_id)
        if not project:
            return {"ok": False, "error": "Project not found"}, 404
        full = project.to_full_dict()
        if "result" in full and full["result"] is not None:
            full["result"] = redact_sensitive_output(full["result"])
        return {"ok": True, "project": full}

    @app.route("/api/projects/<project_id>", methods=["PUT"])
    def update_project(project_id):
        """更新项目"""
        _auth()
        data = request.get_json() or {}
        store = get_project_store()
        success = store.update_project(project_id, data)
        if not success:
            return {"ok": False, "error": "Project not found"}, 404
        return {"ok": True}

    @app.route("/api/projects/<project_id>", methods=["DELETE"])
    def delete_project(project_id):
        """删除项目"""
        _auth()
        store = get_project_store()
        success = store.delete_project(project_id)
        if not success:
            return {"ok": False, "error": "Project not found"}, 404
        return {"ok": True}

    @app.route("/api/projects/<project_id>/translate", methods=["POST"])
    def translate_project(project_id):
        """在项目中执行翻译"""
        _auth()
        data = request.get_json() or {}
        store = get_project_store()

        project = store.get_project(project_id)
        if not project:
            return {"ok": False, "error": "Project not found"}, 404

        config_text = data.get("config_text", "").strip()
        from_vendor = data.get("from_vendor", project.from_vendor)
        to_vendor = data.get("to_vendor", project.to_vendor)
        source_domain = data.get("source_domain", project.source_domain)
        source_platform = data.get("source_platform", project.source_platform)
        target_domain = data.get("target_domain", project.target_domain)
        target_platform = data.get("target_platform", project.target_platform)

        if not config_text:
            return {"ok": False, "error": "No config provided"}

        def _translation_fingerprint(cfg: str, fv: str, tv: str, sd: str, sp: str, td: str, tp: str) -> str:
            import hashlib
            import json
            key = {
                "config_text": cfg.strip(),
                "from_vendor": fv or "",
                "to_vendor": tv or "",
                "source_domain": sd or "",
                "source_platform": sp or "",
                "target_domain": td or "",
                "target_platform": tp or "",
            }
            return hashlib.sha256(json.dumps(key, sort_keys=True, ensure_ascii=True).encode()).hexdigest()

        fingerprint = _translation_fingerprint(
            config_text, from_vendor, to_vendor,
            source_domain, source_platform, target_domain, target_platform,
        )

        if project.result is not None and project.last_translate_hash == fingerprint:
            import time as _time
            return {
                "ok": True,
                "result": redact_sensitive_output(project.result),
                "reused": True,
                "elapsed_ms": 0,
                "request_id": project.request_id or "",
                "version": project.version or "",
                "model": project.model or "",
            }, 200

        # 更新项目配置（不含 last_translate_hash，等翻译成功时一起写入）
        store.update_project(project_id, {
            "config_text": config_text,
            "from_vendor": from_vendor,
            "to_vendor": to_vendor,
            "source_domain": source_domain,
            "source_platform": source_platform,
            "target_domain": target_domain,
            "target_platform": target_platform,
        })

        import uuid
        request_id = str(uuid.uuid4())

        import time as _time
        t0 = _time.time()

        # 执行翻译
        try:
            result_data = run_translation(
                config_text=config_text,
                from_vendor=from_vendor,
                to_vendor=to_vendor,
                source_domain=source_domain,
                source_platform=source_platform,
                target_domain=target_domain,
                target_platform=target_platform,
                user="web_user",
            )
        except Exception:
            logger.exception("Project translation failed for project %s", project_id)
            elapsed = _time.time() - t0
            _write_translation_log(
                request_id, elapsed, config_text,
                from_vendor, to_vendor, source_domain, source_platform,
                target_domain, target_platform, result=None, error="Internal translation error",
            )
            return {"ok": False, "error": "Internal translation error", "request_id": request_id}, 500

        # 敏感信息脱敏：递归 redact 所有字符串字段
        result_data = redact_sensitive_output(result_data)

        # 翻译成功后：同时写入 result 和 fingerprint，避免中途失败导致旧 result 绑定新 fingerprint
        store.update_project(project_id, {
            "result": result_data,
            "request_id": request_id,
            "version": _read_version(),
            "model": _get_model_name(),
            "last_translate_hash": fingerprint,
        })

        store.add_history(project_id, {
            "config_text": config_text,
            "from_vendor": from_vendor,
            "to_vendor": to_vendor,
            "source_domain": source_domain,
            "source_platform": source_platform,
            "target_domain": target_domain,
            "target_platform": target_platform,
            "success": result_data.get("success", False),
            "translated": result_data.get("translated", ""),
        })

        import time as _time
        elapsed = _time.time() - t0
        _write_translation_log(
            request_id, elapsed, config_text,
            from_vendor, to_vendor, source_domain, source_platform,
            target_domain, target_platform, result_data, error=None,
        )

        return {
            "ok": True,
            "request_id": request_id,
            "version": _read_version(),
            "model": _get_model_name(),
            "result": result_data,
        }
