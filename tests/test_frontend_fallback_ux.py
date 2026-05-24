# -*- coding: utf-8 -*-
"""Static checks for frontend fallback UX messaging."""

import re

INDEX_HTML = "frontend/index.html"


def _read():
    with open(INDEX_HTML, encoding="utf-8") as f:
        return f.read()


def test_frontend_has_rule_fallback_warning_message():
    content = _read()
    assert "规则兜底" in content, "Frontend must contain '规则兜底' label"


def test_frontend_has_llm_structured_result_message():
    content = _read()
    assert "没有得到可验证的 LLM 结构化结果" in content, (
        "Frontend must contain the user-friendly LLM failure message"
    )


def test_frontend_has_human_review_summary_message():
    content = _read()
    assert "人工复核摘要" in content, (
        "Frontend must mention '人工复核摘要' so users know where to look"
    )


def test_frontend_renders_fallback_notice_in_risk_tab():
    content = _read()
    assert "fallback_used" in content, "Frontend must check fallback_used flag"
    assert "risk--review" in content, "Frontend must use risk--review class for fallback notice"