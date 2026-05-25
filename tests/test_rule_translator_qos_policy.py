# -*- coding: utf-8 -*-
"""QoS / traffic-policy translation tests for Batch I-F.

Covers:
- Huawei traffic-policy P inbound -> Cisco service-policy input P (binding only)
- Cisco service-policy input P -> Huawei traffic-policy P inbound (binding only)
- Policy body (class-map/policy-map/car/remark/queue/priority/police): MANUAL_REVIEW
"""

import pytest
from core.rule_translator import RuleBasedTranslator


def _executable_lines(text: str):
    return [
        l for l in text.split("\n")
        if l.strip() and not l.strip().startswith("#") and not l.strip().startswith("!")
    ]


def _has_source_syntax(result: str, source_vendor: str) -> bool:
    source_vendor = source_vendor.lower()
    if source_vendor == "cisco":
        return any(k in result for k in [
            "ip access-group", "switchport",
        ])
    if source_vendor in ("huawei", "huawei_usg"):
        return any(k in result for k in [
            "port link-type", "port trunk allow-pass",
            "traffic-filter", "acl number",
            "vlan batch", "ntp-service",
            "info-center", "snmp-agent community",
        ])
    return False


class TestHuaweiTrafficPolicyToCisco:
    """Huawei traffic-policy binding -> Cisco service-policy"""

    def test_huawei_traffic_policy_inbound_auto(self):
        result = RuleBasedTranslator().translate(
            "traffic-policy P inbound\n",
            "huawei", "cisco",
        )
        assert "service-policy input P" in result, \
            f"Expected service-policy input P: {result}"

    def test_huawei_traffic_policy_outbound_manual_review(self):
        result = RuleBasedTranslator().translate(
            "traffic-policy P outbound\n",
            "huawei", "cisco",
        )
        assert "MANUAL_REVIEW" in result, \
            "outbound traffic-policy should be MANUAL_REVIEW"

    def test_huawei_traffic_policy_body_manual_review(self):
        config = """traffic-policy P inbound
 traffic-filter classifier CLASS-A precedence 10
"""
        result = RuleBasedTranslator().translate(config, "huawei", "cisco")
        assert "MANUAL_REVIEW" in result, \
            "traffic-policy body should be MANUAL_REVIEW"


class TestCiscoServicePolicyToHuawei:
    """Cisco service-policy binding -> Huawei traffic-policy"""

    def test_cisco_service_policy_input_auto(self):
        result = RuleBasedTranslator().translate(
            "service-policy input P\n",
            "cisco", "huawei",
        )
        assert "traffic-policy P inbound" in result, \
            f"Expected traffic-policy P inbound: {result}"

    def test_cisco_service_policy_output_manual_review(self):
        result = RuleBasedTranslator().translate(
            "service-policy output P\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in result, \
            "outbound service-policy should be MANUAL_REVIEW"

    def test_cisco_policy_map_body_manual_review(self):
        config = """policy-map PM-TEST
 class CLASS-WEB
  priority
  police 8000
"""
        result = RuleBasedTranslator().translate(config, "cisco", "huawei")
        assert "MANUAL_REVIEW" in result, \
            "policy-map body should be MANUAL_REVIEW"


class TestQoSNoSourceSyntaxResidue:
    """QoS translations should not leave source vendor syntax"""

    def test_huawei_traffic_policy_no_huawei_syntax_in_cisco(self):
        result = RuleBasedTranslator().translate(
            "traffic-policy P inbound\n",
            "huawei", "cisco",
        )
        _has_source_syntax(result, "huawei")
        assert not _has_source_syntax(result, "huawei"), \
            "No Huawei source syntax should appear in Cisco output"

    def test_cisco_service_policy_no_cisco_syntax_in_huawei(self):
        result = RuleBasedTranslator().translate(
            "service-policy input P\n",
            "cisco", "huawei",
        )
        assert not _has_source_syntax(result, "cisco"), \
            "No Cisco source syntax should appear in Huawei output"


class TestQoSNoImplicitAny:
    """No implicit any in QoS translations"""

    def test_traffic_policy_no_any(self):
        result = RuleBasedTranslator().translate(
            "traffic-policy P inbound\n",
            "huawei", "cisco",
        )
        executable = "\n".join(_executable_lines(result))
        assert "any" not in executable.lower(), \
            "No implicit any should appear"
