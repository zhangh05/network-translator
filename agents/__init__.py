# -*- coding: utf-8 -*-
"""NetworkTranslatorAgent compatibility wrapper on top of GraphAgent."""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Dict, Optional

from core import LLM
from core.graph.agent import GraphAgent


class NetworkTranslatorAgent:
    name = "Network Translator Assistant"
    description = "Graph-driven translator agent"

    def __init__(
        self,
        knowledge_dir: str = "knowledge_data",
        memory_dir: str = "memory_data",
        llm: Optional[LLM] = None,
    ):
        self.llm = llm or LLM(
            api_key=os.environ.get("LLM_API_KEY", ""),
            model=os.environ.get("LLM_MODEL", "MiniMax-M2.7"),
        )
        self.graph_agent = GraphAgent(
            knowledge_dir=knowledge_dir,
            memory_dir=memory_dir,
            enable_diff=True,
            enable_fallback=True,
            llm=self.llm,
        )
        self.working_memory = self.graph_agent.working_memory
        self.episodic_memory = self.graph_agent.episodic_memory
        self.semantic_memory = self.graph_agent.semantic_memory
        self.messages = []
        self._tools: Dict[str, callable] = {
            "parse_config": self._tool_parse_config,
            "translate_with_llm": self._tool_translate,
            "get_knowledge": self._tool_get_knowledge,
            "diff_config": self._tool_diff_config,
            "validate_config": self._tool_validate_config,
            "get_history": self._tool_get_history,
        }

    @property
    def tools(self) -> Dict[str, callable]:
        return self._tools

    def translate(
        self,
        config_text: str,
        from_vendor: str = "auto",
        to_vendor: str = "huawei",
        user: str = "anonymous",
    ) -> str:
        if from_vendor == "auto":
            from tools import ConfigParser

            parsed = ConfigParser().parse(config_text)
            if parsed.vendor and parsed.vendor != "unknown":
                from_vendor = parsed.vendor
            else:
                from_vendor = "cisco"

        result = self.graph_agent.run(
            config_text=config_text,
            from_vendor=from_vendor,
            to_vendor=to_vendor,
            user=user,
        )
        return result.get("translated", "")

    def _tool_parse_config(self, config_text: str, vendor_hint: str = None) -> str:
        from tools import ConfigParser

        parsed = ConfigParser().parse(config_text, vendor_hint)
        summary = {
            "vendor": parsed.vendor,
            "hostname": parsed.hostname,
            "interfaces": [i.name for i in parsed.interfaces],
            "vlan_count": len(parsed.vlans),
            "acl_count": len(parsed.acl_configs),
        }
        return json.dumps(summary, ensure_ascii=False, indent=2)

    def _tool_translate(self, config_text: str, from_vendor: str, to_vendor: str) -> str:
        return self.translate(config_text, from_vendor, to_vendor)

    def _tool_get_knowledge(self, from_vendor: str, to_vendor: str) -> str:
        from tools import KnowledgeRetriever

        return KnowledgeRetriever("knowledge_data").get_all_mapping_info(from_vendor, to_vendor)

    def _tool_diff_config(self, original: str, translated: str, from_vendor: str, to_vendor: str) -> str:
        from tools import ConfigDiffer, ConfigParser

        parser = ConfigParser()
        differ = ConfigDiffer()
        orig_parsed = parser.parse(original, from_vendor)
        trans_parsed = parser.parse(translated, to_vendor)
        diffs = differ.diff(orig_parsed, trans_parsed)
        lines = ["## Diff Report", ""]
        if not diffs:
            lines.append("(no major differences)")
        else:
            for d in diffs:
                lines.append(f"- **{d.diff_type}** @ {d.location}")
                lines.append(f"  original: `{d.original}`")
                lines.append(f"  translated: `{d.translated}`")
        return "\n".join(lines)

    def _tool_validate_config(self, config_text: str, vendor: str) -> str:
        from tools import ConfigParser, ConfigValidator

        parser = ConfigParser()
        validator = ConfigValidator()
        parsed = parser.parse(config_text, vendor)
        result = validator.validate(parsed)
        lines = ["## Validation", ""]
        lines.append("PASS" if result.valid else "FAIL")
        if result.errors:
            lines.append("Errors:")
            lines.extend(f"- {e}" for e in result.errors)
        if result.warnings:
            lines.append("Warnings:")
            lines.extend(f"- {w}" for w in result.warnings)
        return "\n".join(lines)

    def _tool_get_history(self, query: str = None, limit: int = 10) -> str:
        from memory import EpisodicMemory

        events = EpisodicMemory("memory_data").search(query=query, limit=limit)
        if not events:
            return "(empty history)"
        lines = ["## History", ""]
        for e in events:
            lines.append(f"- [{e.timestamp[:10]}] {e.from_vendor}->{e.to_vendor}: {e.summary[:80]}")
        return "\n".join(lines)

    def generate_report(
        self,
        original: str,
        translated: str,
        from_vendor: str,
        to_vendor: str,
        summary: str = "",
    ) -> str:
        lines = [
            "# Translation Report",
            "",
            f"**time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**direction**: {from_vendor.upper()} -> {to_vendor.upper()}",
        ]
        if summary:
            lines.append(f"**summary**: {summary}")
        lines.extend(["", "## Translated Config", "", "```", translated, "```", ""])
        return "\n".join(lines)

    def think(self, user_input: str, system: str = None) -> str:
        if len(self._tools) > 5 and hasattr(self, "llm"):
            messages = [{"role": "user", "content": user_input}]
            tools_schema = self._get_tools_schema()
            result = {"content": ""}
            for _ in range(5):
                result = self.llm.chat(
                    messages=messages,
                    system=system or "You are a network configuration assistant.",
                    tools=tools_schema,
                )
                if result.get("error"):
                    return self.translate(user_input, "auto", "huawei")
                if not result.get("tool_calls"):
                    content = result.get("content", "")
                    return content if content else self.translate(user_input, "auto", "huawei")

                for tc in result.get("tool_calls", []):
                    tool_name = tc.get("name", "")
                    args = tc.get("input", {}) or {}
                    if tool_name in self._tools:
                        tool_result = self._tools[tool_name](**args)
                        messages.append(
                            {"role": "assistant", "content": "", "tool_call_id": tc.get("id", ""), "name": tool_name}
                        )
                        messages.append({"role": "tool", "name": tool_name, "content": str(tool_result)})
            content = result.get("content", "")
            return content if content else self.translate(user_input, "auto", "huawei")

        return self.translate(user_input, "auto", "huawei")

    def _get_tools_schema(self):
        import inspect

        schemas = []
        for name, func in self.tools.items():
            sig = inspect.signature(func)
            params = {}
            for pname in sig.parameters:
                if pname in ("self", "kwargs", "session_meta"):
                    continue
                params[pname] = {"type": "string"}
            schemas.append(
                {
                    "name": name,
                    "description": func.__doc__ or f"tool: {name}",
                    "input_schema": {"type": "object", "properties": params},
                }
            )
        return schemas if schemas else None

    def tool(self, name: str = None):
        def decorator(func):
            self.tools[name or func.__name__] = func
            return func

        return decorator

    def reset(self):
        return None

    def __repr__(self):
        return f"<NetworkTranslatorAgent graph={self.graph_agent.graph.name}>"

