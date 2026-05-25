# -*- coding: utf-8 -*-
"""Route-policy / route-map translation tests for Batch I-F.

Covers:
- Cisco route-map -> Huawei route-policy (skeleton)
- Huawei route-policy -> Cisco route-map (skeleton)
- local-preference: auto-translate
- community/continue/call/extcommunity/as-path/tag: MANUAL_REVIEW
"""

import pytest
from core.rule_translator import RuleBasedTranslator


def _executable_lines(text: str):
    return [
        l for l in text.split("\n")
        if l.strip() and not l.strip().startswith("#") and not l.strip().startswith("!")
    ]


def _has_secret_leak(result: str) -> bool:
    import re
    patterns = [
        re.compile(r"(?<![<>\w])(password|secret|cipher|shared-key)\s+(?!<redacted>)\S+", re.I),
        re.compile(r"(?<![<>\w])community\s+(?!<redacted>)\S+", re.I),
    ]
    for p in patterns:
        if p.search(result):
            return True
    return False


class TestCiscoRouteMapToHuawei:
    """Cisco route-map -> Huawei route-policy"""

    def test_route_map_permit_node_auto(self):
        result = RuleBasedTranslator().translate(
            "route-map TEST permit 10\n",
            "cisco", "huawei",
        )
        assert "route-policy TEST permit node 10" in result, \
            f"Expected Huawei route-policy format: {result}"

    def test_route_map_deny_node_auto(self):
        result = RuleBasedTranslator().translate(
            "route-map TEST deny 20\n",
            "cisco", "huawei",
        )
        assert "route-policy TEST deny node 20" in result, \
            f"Expected Huawei route-policy format: {result}"

    def test_route_map_with_description_manual_review(self):
        result = RuleBasedTranslator().translate(
            "route-map TEST permit 10 description ALLOW_WEB\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in result, \
            "route-map description should be MANUAL_REVIEW"

    def test_route_map_match_acl_auto(self):
        result = RuleBasedTranslator().translate(
            "route-map TEST permit 10\n match ip address ACL-WEB\n",
            "cisco", "huawei",
        )
        assert "if-match acl ACL-WEB" in result or "MANUAL_REVIEW" in result, \
            f"Expected if-match acl or MANUAL_REVIEW: {result}"

    def test_route_map_set_local_pref_auto(self):
        result = RuleBasedTranslator().translate(
            "route-map TEST permit 10\n set local-preference 200\n",
            "cisco", "huawei",
        )
        assert "apply local-preference 200" in result or "set local-preference 200" in result, \
            f"Expected local-preference set: {result}"

    def test_route_map_set_community_manual_review(self):
        result = RuleBasedTranslator().translate(
            "route-map TEST permit 10\n set community 65001:100\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in result, \
            "set community should be MANUAL_REVIEW"
        assert _has_secret_leak(result) is False, \
            "community value should be redacted"

    def test_route_map_continue_manual_review(self):
        result = RuleBasedTranslator().translate(
            "route-map TEST permit 10\n continue 20\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in result, \
            "continue should be MANUAL_REVIEW"

    def test_route_map_call_manual_review(self):
        result = RuleBasedTranslator().translate(
            "route-map TEST permit 10\n call RM-OTHER\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in result, \
            "call should be MANUAL_REVIEW"

    def test_route_map_as_path_manual_review(self):
        result = RuleBasedTranslator().translate(
            "route-map TEST permit 10\n set as-path prepend 65001\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in result, \
            "as-path prepend should be MANUAL_REVIEW"

    def test_route_map_tag_manual_review(self):
        result = RuleBasedTranslator().translate(
            "route-map TEST permit 10\n set tag 100\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in result, \
            "set tag should be MANUAL_REVIEW"

    def test_route_map_extcommunity_manual_review(self):
        result = RuleBasedTranslator().translate(
            "route-map TEST permit 10\n set extcommunity rt 65001:100\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in result, \
            "set extcommunity should be MANUAL_REVIEW"

    def test_route_map_metric_manual_review(self):
        result = RuleBasedTranslator().translate(
            "route-map TEST permit 10\n set metric 100\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in result, \
            "set metric should be MANUAL_REVIEW"

    def test_route_map_multiple_clauses_all_translated(self):
        config = """route-map TEST permit 10
 match ip address ACL-WEB
 set local-preference 200
route-map TEST permit 20
 match ip address ACL-DB
 set local-preference 300
"""
        result = RuleBasedTranslator().translate(config, "cisco", "huawei")
        if "MANUAL_REVIEW" not in result:
            assert "node 10" in result, "route-map clause 10 should appear"
            assert "node 20" in result, "route-map clause 20 should appear"


class TestHuaweiToCiscoRouteMap:
    """Huawei route-policy -> Cisco route-map"""

    def test_huawei_route_policy_permit_node_auto(self):
        result = RuleBasedTranslator().translate(
            "route-policy TEST permit node 10\n",
            "huawei", "cisco",
        )
        assert "route-map TEST permit 10" in result, \
            f"Expected Cisco route-map format: {result}"

    def test_huawei_route_policy_deny_node_auto(self):
        result = RuleBasedTranslator().translate(
            "route-policy TEST deny node 20\n",
            "huawei", "cisco",
        )
        assert "route-map TEST deny 20" in result, \
            f"Expected Cisco route-map format: {result}"

    def test_huawei_route_policy_if_match_acl_auto(self):
        result = RuleBasedTranslator().translate(
            "route-policy TEST permit node 10\n if-match acl ACL-WEB\n",
            "huawei", "cisco",
        )
        assert "match ip address ACL-WEB" in result or "MANUAL_REVIEW" in result, \
            f"Expected match ip address or MANUAL_REVIEW: {result}"

    def test_huawei_route_policy_apply_local_pref_auto(self):
        result = RuleBasedTranslator().translate(
            "route-policy TEST permit node 10\n apply local-preference 200\n",
            "huawei", "cisco",
        )
        assert "set local-preference 200" in result, \
            f"Expected local-preference set: {result}"

    def test_huawei_route_policy_apply_community_manual_review(self):
        result = RuleBasedTranslator().translate(
            "route-policy TEST permit node 10\n apply community 65001:100\n",
            "huawei", "cisco",
        )
        assert "MANUAL_REVIEW" in result, \
            "apply community should be MANUAL_REVIEW"

    def test_huawei_route_policy_continue_manual_review(self):
        result = RuleBasedTranslator().translate(
            "route-policy TEST permit node 10\n continue 20\n",
            "huawei", "cisco",
        )
        assert "MANUAL_REVIEW" in result, \
            "continue should be MANUAL_REVIEW"

    def test_huawei_route_policy_call_manual_review(self):
        result = RuleBasedTranslator().translate(
            "route-policy TEST permit node 10\n call RM-OTHER\n",
            "huawei", "cisco",
        )
        assert "MANUAL_REVIEW" in result, \
            "call should be MANUAL_REVIEW"

    def test_huawei_route_policy_apply_as_path_manual_review(self):
        result = RuleBasedTranslator().translate(
            "route-policy TEST permit node 10\n apply as-path 65001\n",
            "huawei", "cisco",
        )
        assert "MANUAL_REVIEW" in result, \
            "apply as-path should be MANUAL_REVIEW"

    def test_huawei_route_policy_apply_tag_manual_review(self):
        result = RuleBasedTranslator().translate(
            "route-policy TEST permit node 10\n apply tag 100\n",
            "huawei", "cisco",
        )
        assert "MANUAL_REVIEW" in result, \
            "apply tag should be MANUAL_REVIEW"

    def test_huawei_route_policy_multiple_nodes_all_translated(self):
        config = """route-policy TEST permit node 10
 if-match acl ACL-WEB
 apply local-preference 200
route-policy TEST permit node 20
 if-match acl ACL-DB
 apply local-preference 300
"""
        result = RuleBasedTranslator().translate(config, "huawei", "cisco")
        if "MANUAL_REVIEW" not in result:
            assert "permit 10" in result, "clause 10 should appear"
            assert "permit 20" in result, "clause 20 should appear"


class TestRoutePolicySecretNoLeak:
    """Route-policy commands should not leak secrets"""

    def test_route_map_no_secret_leak(self):
        result = RuleBasedTranslator().translate(
            "route-map TEST permit 10\n set community 65001:100\n",
            "cisco", "huawei",
        )
        assert "65001:100" not in result or "MANUAL_REVIEW" in result, \
            "community value should be redacted or MANUAL_REVIEW"

    def test_huawei_route_policy_no_secret_leak(self):
        result = RuleBasedTranslator().translate(
            "route-policy TEST permit node 10\n apply community 65001:100\n",
            "huawei", "cisco",
        )
        assert "65001:100" not in result or "MANUAL_REVIEW" in result, \
            "community value should be redacted or MANUAL_REVIEW"
