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

    def test_notice_explains_llm_was_attempted_but_validation_failed(self):
        notice = _fallback_notice_text()
        assert "LLM 已尝试翻译" in notice, \
            f"Notice should not imply LLM was skipped entirely: {notice[:200]}"
        assert "结构化校验未通过" in notice, \
            f"Notice should explain fallback is caused by validation failure: {notice[:200]}"

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

    def test_desktop_layout_keeps_source_and_result_side_by_side(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert 'id="scard"' in html, "source card needs a stable id for desktop split layout"
        assert "@media(min-width:1100px)" in html, "desktop split layout media query missing"
        assert "grid-template-columns" in html and "#scard" in html and "#rcard" in html, \
            "desktop layout should keep source and result visible side by side"

    def test_desktop_layout_gives_source_independent_scroll(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "#source{height:calc(100% - 40px)" in html, \
            "desktop source textarea should fill its own card instead of disappearing above results"
        assert "#rcard{height:calc(100vh - 128px)" in html, \
            "desktop result card should have its own bounded height"

    def test_copy_deployable_uses_deployable_config_first(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "r.deployable_config" in html and "_copyDeployable" in html, \
            "_copyDeployable should reference r.deployable_config"

    def test_export_report_includes_deployable_config(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "deployable_config:stripFence" in html or "deployable_config" in html, \
            "_buildExportReport should include deployable_config"


class TestFallbackModeTranslatedTab:

    def test_translated_tab_renders_deployable_config_even_when_fallback_used(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "_deployableOnlyText(r)" in html, \
            "RN() must render filtered deployable-only text"

    def test_translated_tab_filters_manual_review_lines(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "function _deployableOnlyText" in html, \
            "translated tab needs a deployable-only helper"
        assert 'l.indexOf("MANUAL_REVIEW")===-1' in html, \
            "translated tab must filter MANUAL_REVIEW lines out of deployable view"

    def test_translated_tab_has_empty_deployable_message(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "无可部署配置" in html and "请查看风险分析" in html, \
            "translated tab should guide users when only manual-review lines remain"

    def test_translated_tab_does_not_show_人工复核摘要(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        rn_match = re.search(r"function RN\(\).*?\{", html, re.DOTALL)
        assert rn_match, "RN() function not found"
        rn_body_start = rn_match.end()
        rn_close = html.find("}", rn_body_start)
        snippet = html[rn_body_start:rn_close+20]
        assert "人工复核摘要" not in snippet, \
            "RN() translated tab must not show '人工复核摘要' — that belongs in risk tab"

    def test_translated_tab_does_not_show_fallback_reason_internal_field(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        rn_match = re.search(r"function RN\(\).*?\{", html, re.DOTALL)
        assert rn_match
        rn_body_start = rn_match.end()
        rn_close = html.find("}", rn_body_start)
        snippet = html[rn_body_start:rn_close+20]
        assert "fallback_reason=" not in snippet, \
            "RN() must not expose fallback_reason internal field in translated tab"

    def test_translated_tab_does_not_show_block_count_internal_field(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        rn_match = re.search(r"function RN\(\).*?\{", html, re.DOTALL)
        assert rn_match
        rn_body_start = rn_match.end()
        rn_close = html.find("}", rn_body_start)
        snippet = html[rn_body_start:rn_close+20]
        assert "block_count=" not in snippet, \
            "RN() must not expose block_count internal field in translated tab"

    def test_risk_tab_shows_fallback_notice_with_chinese_categories(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "风险分析" in html, "risk tab label not found"
        assert "fallbackNotice" in html or "r.fallback_used" in html, \
            "risk tab must show fallback notice when fallback_used=true"
        assert "人工复核摘要" in html, \
            "risk tab must reference 人工复核摘要 in fallback notice"

    def test_validation_tab_shows_manual_review_required_field(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "需人工复核" in html, \
            "validation tab must show manual review required status"
        assert "manual_review_required" in html, \
            "validation rendering must use manual_review_required field"


class TestUserFriendlyRiskAndDiffTabs:
    def test_risk_tab_is_launch_checklist_not_internal_categories(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        for label in ("上线检查清单", "上线结论", "上线前必须处理", "需要人工确认", "系统已自动处理"):
            assert label in html, f"risk tab should contain user-facing label: {label}"

    def test_risk_tab_keeps_raw_details_collapsed(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "原始技术细节" in html, "risk tab should keep raw technical details in a collapsed section"
        assert "_renderRiskRawDetails" in html, "risk tab should have a dedicated raw details renderer"

    def test_diff_tab_is_change_explanation_not_raw_diff_first(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        for label in ("变更说明", "自动映射", "需要确认的变化", "未迁移 / 不支持"):
            assert label in html, f"diff tab should contain user-facing label: {label}"

    def test_diff_tab_has_user_sentence_helper(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "_diffLineToUserText" in html, "diff tab should translate raw diff lines into user sentences"


class TestManualReviewTab:
    def test_manual_review_tab_exists_as_separate_option(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert 'data-tab="review"' in html, "manual review must be a separate tab"
        assert "人工复核" in html, "manual review tab label should be visible"

    def test_manual_review_tab_has_dedicated_renderer(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "function _renderManualReviewTab" in html, "manual review tab needs its own renderer"
        assert "review:_renderManualReviewTab(r)" in html, "RN() should route review tab to renderer"

    def test_manual_review_tab_shows_source_lines_and_reason(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        for label in ("原配置片段", "原因", "建议动作"):
            assert label in html, f"manual review item should expose {label}"
        assert "source_lines" in html, "manual review should use analyzer/capability source_lines"

    def test_manual_review_tab_uses_module_graph_first(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "r.module_graph" in html, "manual review tab should consume module_graph from API result"
        assert "manual_review_reason" in html, "module graph manual_review_reason should be displayed"
        assert "depends_on" in html and "provides" in html and "consumes" in html, \
            "module graph dependencies should be visible to users"

    def test_manual_review_tab_extracts_manual_review_source_commands(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "_extractManualReviewCommands" in html, \
            "manual review should extract original commands from MANUAL_REVIEW comments"
        assert "unsupported source command" in html, \
            "manual review should parse unsupported source command comments"
