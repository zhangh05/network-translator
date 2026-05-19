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
        self.history = []

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
            "history_count": len(self.history),
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
        self._load_index()

    def _ensure_fresh(self):
        if time.time() - self._last_load > self._INDEX_TTL:
            self._load_index()

    @staticmethod
    def _locked_write(filepath: Path, write_fn):
        """Write with exclusive file lock."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                write_fn(f)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _locked_read(filepath: Path) -> Optional[dict]:
        """Read with shared file lock."""
        if not filepath.exists():
            return None
        with open(filepath, "r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                return json.load(f)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def _load_index(self):
        """加载项目索引"""
        self._projects.clear()
        try:
            data = self._locked_read(self.meta_file)
            if data:
                for p in data.get("projects", []):
                    proj = Project(p["id"], p["name"])
                    proj.created_at = p.get("created_at", proj.created_at)
                    proj.updated_at = p.get("updated_at", proj.created_at)
                    proj.config_text = p.get("config_text", "")
                    proj.from_vendor = p.get("from_vendor", "auto")
                    proj.to_vendor = p.get("to_vendor", "huawei")
                    proj.source_domain = p.get("source_domain", "")
                    proj.source_platform = p.get("source_platform", "")
                    proj.target_domain = p.get("target_domain", "")
                    proj.target_platform = p.get("target_platform", "")
                    self._projects[p["id"]] = proj
        except Exception:
            logger.exception("Failed to load project index")
        self._last_load = time.time()

    def _save_index(self):
        """保存项目索引"""
        try:
            data = {"projects": [p.to_dict() for p in self._projects.values()]}
            self._locked_write(self.meta_file, lambda f: json.dump(data, f, indent=2, ensure_ascii=False))
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

    def get_project(self, project_id: str) -> Optional[Project]:
        """获取项目"""
        self._ensure_fresh()
        if project_id in self._projects:
            filepath = self._get_project_file(project_id)
            try:
                data = self._locked_read(filepath)
                if data:
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
                    proj.history = data.get("history", [])
                    self._projects[project_id] = proj
                    return proj
            except Exception:
                logger.exception("Failed to read project %s", project_id)
        return self._projects.get(project_id)

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
            project.result = updates["result"]

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
        if project_id in self._projects:
            del self._projects[project_id]
            filepath = self._get_project_file(project_id)
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
        return {"ok": True, "project": project.to_full_dict()}

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

        # 更新项目配置
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
            return {"ok": False, "error": "Internal translation error", "request_id": request_id}, 500

        store.update_project(project_id, {"result": result_data})

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

        return {
            "ok": True,
            "request_id": request_id,
            "version": _read_version(),
            "model": _get_model_name(),
            "result": result_data,
        }
