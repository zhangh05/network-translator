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
        assert "manual_review_config" in html and "module_translations" in html, \
            "_buildExportReport should include separated manual-review module output"


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


class TestUserFriendlyRiskAndSemanticTabs:
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

    def test_semantic_tab_replaces_raw_diff_with_module_pairs(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert 'data-tab="semantic"' in html, "semantic near-match tab should replace raw diff tab"
        assert "配置语义相近" in html, "tab should use user-facing semantic label"
        for label in ("原配置模块", "建议目标配置", "语义判断", "确认点"):
            assert label in html, f"semantic tab should contain module-pair label: {label}"

    def test_semantic_tab_uses_module_translation_results(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "function _renderSemanticNearTab" in html, "semantic tab needs a dedicated renderer"
        assert "module_translations" in html and "translated_lines" in html and "source_lines" in html, \
            "semantic tab should derive near matches from module translation evidence"
        assert "suggested_lines" in html and "semantic_near" in html, \
            "semantic tab should show non-deployable suggested target lines for conservative modules"

    def test_raw_diff_is_not_primary_user_tab(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "差异对比" not in html, "raw diff should not be a primary user tab"
        assert "_renderDiffTab" not in html, "old raw diff renderer should be removed from primary UI"


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

    def test_manual_review_tab_groups_items_by_user_categories(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "function _reviewGroupForFeature" in html, \
            "manual review tab should map technical features into user-facing groups"
        for label in ("接口与 VLAN", "路由与转发", "ACL 与安全策略", "防火墙对象", "QoS 与流量策略", "未支持能力"):
            assert label in html, f"manual review grouping should include {label}"

    def test_manual_review_tab_shows_summary_counts(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "复核总数" in html, "manual review tab should show total review item count"
        assert "review-summary" in html, "manual review summary should have a dedicated CSS class"
        assert "review-group__count" in html, "manual review groups should show per-group counts"

    def test_manual_review_tab_translates_coupling_relations(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "function _moduleCouplingLabel" in html, \
            "manual review tab should translate module coupling names"
        for label in ("对象组成员", "ACL 引用对象组", "策略使用时间段", "BGP 引用路由策略", "QoS 绑定接口"):
            assert label in html, f"manual review coupling label should include {label}"

    def test_manual_review_tab_has_object_group_member_labels(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "object_group.member" in html, "manual review tab should recognize object-group member modules"
        assert "对象组成员" in html, "object-group member modules should be displayed with a user-facing label"

    def test_copy_report_includes_manual_review_checklist(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "function _manualReviewChecklistLines" in html, \
            "copy/export report should share a user-facing manual-review checklist builder"
        assert "--- 人工复核清单 ---" in html, \
            "copied risk report should include a dedicated manual-review checklist section"

    def test_export_report_includes_manual_review_checklist(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "manual_review_checklist" in html, \
            "exported JSON report should include user-facing manual review checklist"

    def test_manual_review_tab_derives_review_priority(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "function _reviewPriorityForItem" in html, \
            "manual review items should derive a user-facing review priority"
        for label in ("必须处理", "需要确认", "信息提示"):
            assert label in html, f"manual review priority should include {label}"

    def test_manual_review_tab_sorts_by_review_priority(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "function _sortManualReviewItems" in html, \
            "manual review items should share one priority-aware sort helper"
        assert "_sortManualReviewItems(_manualReviewItems(r))" in html, \
            "manual review renderer/checklist should sort items before grouping"
        assert "review-priority--must" in html and "review-priority--confirm" in html, \
            "manual review cards should expose priority classes for scanning"

    def test_manual_review_tab_has_group_filter_controls(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "function _setReviewGroupFilter" in html, \
            "manual review tab should provide a group filter interaction"
        assert "review-filter__btn" in html and "data-review-group-id" in html, \
            "manual review filter should render stable per-group buttons"
        assert "全部" in html, "manual review filter should include an all-items button"

    def test_manual_review_group_filter_does_not_change_export_scope(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "manual_review_checklist:_manualReviewChecklistLines(r)" in html, \
            "exported checklist should remain based on all manual-review items"
        assert "_manualReviewChecklistLines" in html and "_setReviewGroupFilter" in html, \
            "filtering should be a view concern, separate from report export"


class TestAccessAuthenticationManualReviewUX:
    def test_access_authentication_has_user_facing_group(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "准入认证" in html, "access-auth modules should have a dedicated user-facing group"
        assert "access-auth" in html, "access-auth tags should be recognized by the manual-review UI"

    def test_access_authentication_feature_names_are_friendly(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        for label in ("认证模板", "802.1X", "MAC 认证", "Portal 认证", "RADIUS / Domain 绑定", "接口准入绑定"):
            assert label in html, f"manual-review UI should expose friendly access-auth label: {label}"

    def test_access_authentication_review_action_mentions_target_rebuild_and_live_check(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "按目标平台重新设计准入认证" in html, "access-auth action should not imply automatic translation"
        assert "802.1X" in html and "MAC" in html and "Portal" in html and "RADIUS" in html, \
            "access-auth action should name the main NAC mechanisms users must verify"

    def test_access_authentication_coupling_labels_are_translated(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        for label in ("接口绑定认证模板", "接口启用准入认证", "准入认证引用 RADIUS", "准入认证引用 Domain"):
            assert label in html, f"access-auth coupling should have user-facing label: {label}"


class TestManualReviewResourceLabels:
    def test_manual_review_translates_resource_keys_for_access_auth(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "function _resourceLabel" in html, \
            "manual review should translate module resource keys before showing users"
        for label in ("认证模板", "802.1X 模板", "MAC 认证模板", "认证域", "RADIUS 方案"):
            assert label in html, f"module resource label should include {label}"

    def test_module_review_items_use_resource_label_list(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "_resourceLabelList(m.provides)" in html, \
            "provided resources should be user-facing in manual review evidence"
        assert "_resourceLabelList(m.consumes)" in html, \
            "consumed resources should be user-facing in manual review evidence"

    def test_resource_labels_cover_routing_firewall_and_policy_resources(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        for label in ("VLAN", "接口", "ACL", "路由策略", "路由过滤器", "安全域", "地址对象", "服务对象"):
            assert label in html, f"resource labels should cover common module resource type: {label}"


class TestModuleTranslationCoverageView:
    def test_validation_tab_renders_module_translation_coverage(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "function _renderModuleCoverage" in html, \
            "validation tab should render module-level translation coverage"
        for label in ("模块翻译覆盖", "总模块", "已翻译", "部分翻译", "人工复核", "未覆盖"):
            assert label in html, f"module coverage view should expose label: {label}"

    def test_validation_tab_passes_full_result_to_module_coverage_renderer(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "validation:_renderValidationTab(r.validation||r.semantic_validation||{},r)" in html, \
            "validation renderer needs full result to read module_translation_coverage"
        assert "module_translation_coverage" in html and "module_translations" in html, \
            "module coverage renderer should support both API coverage locations"

    def test_module_coverage_explains_unaccounted_modules_as_blocking(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "存在未覆盖模块" in html, \
            "missing module ids should be explained as a blocking coverage issue"
        assert "所有模块都有处理结果" in html, \
            "accounted modules should show a reassuring user-facing message"


class TestProjectTranslationStatusUX:
    def test_project_list_maps_translation_status_from_backend(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "translation_status:p.translation_status||\"idle\"" in html, \
            "project list should preserve backend translation_status for cross-browser visibility"
        assert "active_request_id:p.active_request_id||\"\"" in html, \
            "project list should preserve active_request_id while translation is running"

    def test_sidebar_shows_translating_badge(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "正在翻译" in html, "sidebar should show a user-facing translating badge"
        assert "project-busy" in html, "sidebar translating badge should have a stable CSS class"

    def test_save_project_does_not_overwrite_backend_inflight_status(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        save_start = html.index("async function saveProject")
        save_end = html.index("async function createProject", save_start)
        snippet = html[save_start:save_end]
        assert "translation_status" not in snippet, \
            "ordinary project saves must not clear backend-owned in-flight translation state"

    def test_translation_polling_can_recover_completed_server_result(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "function startTranslationPoll" in html, \
            "frontend needs polling to recover when the POST response is delayed or missed"
        assert "syncActiveProjectFromServer" in html, \
            "polling should reuse one server-sync helper"
        assert "translation_status===\"translating\"" in html, \
            "polling should continue while backend says the project is still translating"

    def test_translation_timeout_message_points_to_saved_result_refresh(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "已超过 3 分钟" in html, \
            "long-running LLM calls need an honest message after the normal window"
        assert "正在尝试从服务端刷新结果" in html, \
            "timeout message should tell users the saved project result is being checked"

class TestSemanticNearWorkbench:
    def test_semantic_tab_has_workbench_controls(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        for token in (
            "semantic-toolbar",
            "semantic-search",
            "data-semantic-filter",
            "_setSemanticFilter",
            "_semanticGroupForFeature",
            "_semanticRiskForModule",
        ):
            assert token in html, f"semantic workbench token missing: {token}"

    def test_semantic_tab_has_user_facing_filters(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        for label in ("全部", "需要确认", "已纳入可部署", "高风险", "路由", "安全", "二层", "IPv6"):
            assert label in html, f"semantic filter label missing: {label}"

    def test_semantic_tab_groups_by_module_family_and_risk(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        for label in ("模块族", "风险", "确认重点", "源行"):
            assert label in html, f"semantic card should expose review metadata: {label}"

    def test_semantic_tab_rendered_as_html_not_pre_wrapped(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert 'tab==="semantic"' in html, "RN() should special-case semantic tab rendering"
        assert 'E("out").innerHTML=views.semantic' in html, "semantic tab should render HTML cards directly"

    def test_semantic_export_still_contains_all_module_matches(self):
        with open(FRONTEND_HTML_PATH, encoding="utf-8") as f:
            html = f.read()
        assert "semantic_near_matches:_semanticNearMatches(r,true)" in html, \
            "export should include unfiltered semantic near matches"
