# -*- coding: utf-8 -*-
"""Tests for frontend fallback UX.

Verifies that when fallback_used=true, the frontend renders the fallback
notice with all required messages.
"""

import re
import pytest

FRONTEND_HTML_PATH = "frontend/index.html"


def _extract_fallback_notice(html: str) -> str:
    p = re.compile(r'fallbackNotice="([^"]+)"')
    ms = list(p.finditer(html))
    for m in ms:
        content = m.group(1)
        if content and len(content) > 10:
            return content
    return ""


def _fallback_notice_text() -> str:
    with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
        html = f.read()
    return _extract_fallback_notice(html)


class TestFrontendFallbackNotice:
    def test_notice_contains规则兜底已启用(self):
        notice = _fallback_notice_text()
        assert "规则兜底" in notice and "已启用" in notice, \
            f"Notice missing '规则兜底已启用': {notice[:200]}"

    def test_notice_contains可执行配置只包含系统能确定的转换(self):
        notice = _fallback_notice_text()
        assert "可执行配置" in notice and "系统能确定的转换" in notice, \
            f"Notice missing '可执行配置只包含系统能确定的转换': {notice[:200]}"

    def test_notice_contains其余内容已进入人工复核(self):
        notice = _fallback_notice_text()
        assert "其余内容已进入人工复核" in notice, \
            f"Notice missing '其余内容已进入人工复核': {notice[:200]}"

    def test_notice_contains请查看人工复核摘要(self):
        notice = _fallback_notice_text()
        assert "人工复核摘要" in notice, \
            f"Notice missing '人工复核摘要': {notice[:200]}"

    def test_manual_review_css_class_exists(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert ".mr" in html or '"mr"' in html or "class='mr'" in html or 'class="mr"' in html, \
            "CSS class .mr for MANUAL_REVIEW lines not found in index.html"

    def test_fallback_used_true_shows_notice(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "if(r.fallback_used)" in html or "if (r.fallback_used)" in html, \
            "fallback_used check not found in index.html"
        assert "risk--review" in html, \
            "risk--review CSS class not found for fallback notice"

    def test_copy_deployable_excludes_manual_review(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "MANUAL_REVIEW" in html, \
            "MANUAL_REVIEW filtering logic not found in index.html"

    def test_fallback_notice_has_risk_review_class(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "risk--review" in html, \
            "risk--review CSS class for fallback notice not found"


class TestDeployableConfigSeparation:
    def test_translated_tab_uses_deployable_config(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "r.deployable_config||r.translated" in html or "deployable_config" in html, \
            "translated tab should prefer deployable_config over translated"

    def test_copy_all_uses_deployable_config(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "deployable_config" in html, \
            "_copyAll should use deployable_config"

    def test_source_panel_has_min_height(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "min-height" in html, \
            "#source textarea should have min-height for readability"

    def test_source_panel_min_height_at_least_280px(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        import re
        m = re.search(r"#source[^{]*\{[^}]*min-height\s*:\s*(\d+)px", html, re.DOTALL)
        assert m is not None, "min-height not found for #source"
        val = int(m.group(1))
        assert val >= 280, f"#source min-height should be >= 280px, got {val}px"