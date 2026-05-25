# -*- coding: utf-8 -*-
"""Firewall service object translation tests for Batch I-F.

Covers:
- Topsec service -> Huawei USG service-set
- Huawei USG service-set -> Hillstone service
- Hillstone service -> Topsec service
- Hillstone service -> Huawei USG service-set
- TCP/UDP single port: auto-translate
- ICMP: auto-translate
- Port range/source-port/multi-port/protocol-number: MANUAL_REVIEW
"""

import pytest
from core.rule_translator import RuleBasedTranslator


def _executable_lines(text: str):
    return [
        l for l in text.split("\n")
        if l.strip() and not l.strip().startswith("#") and not l.strip().startswith("!")
    ]


class TestTopsecToHuaweiUsgServiceObject:
    """Topsec service -> Huawei USG service-set"""

    def test_topsec_service_tcp_port_auto(self):
        result = RuleBasedTranslator().translate(
            "service HTTP protocol tcp destination-port 80\n",
            "topsec", "huawei_usg",
        )
        assert "ip service-set HTTP type object" in result, \
            f"Expected Huawei USG service-set format: {result}"
        assert "protocol tcp" in result or "protocol 6" in result, \
            f"Expected TCP protocol: {result}"
        assert "destination-port 80" in result or "80" in result, \
            f"Expected port 80: {result}"

    def test_topsec_service_udp_port_auto(self):
        result = RuleBasedTranslator().translate(
            "service DNS protocol udp destination-port 53\n",
            "topsec", "huawei_usg",
        )
        assert "ip service-set DNS type object" in result, f"Expected service-set: {result}"
        assert "protocol udp" in result or "protocol 17" in result, \
            f"Expected UDP protocol: {result}"

    def test_topsec_service_icmp_auto(self):
        result = RuleBasedTranslator().translate(
            "service PING protocol icmp\n",
            "topsec", "huawei_usg",
        )
        assert "ip service-set PING type object" in result, f"Expected service-set: {result}"
        assert "protocol icmp" in result or "protocol 1" in result, \
            f"Expected ICMP protocol: {result}"

    def test_topsec_service_port_range_manual_review(self):
        result = RuleBasedTranslator().translate(
            "service HTTPS protocol tcp destination-port 443-443\n",
            "topsec", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in result, \
            "Port range should be MANUAL_REVIEW"

    def test_topsec_service_source_port_manual_review(self):
        result = RuleBasedTranslator().translate(
            "service HTTP protocol tcp source-port 1024 destination-port 80\n",
            "topsec", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in result, \
            "Source-port should be MANUAL_REVIEW"

    def test_topsec_service_multi_port_manual_review(self):
        result = RuleBasedTranslator().translate(
            "service HTTP protocol tcp destination-port 80,443\n",
            "topsec", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in result, \
            "Multi-port should be MANUAL_REVIEW"


class TestHuaweiUsgToHillstoneService:
    """Huawei USG service-set -> Hillstone service"""

    def test_huawei_usg_service_tcp_auto(self):
        result = RuleBasedTranslator().translate(
            "ip service-set HTTP type object\n service 0 protocol tcp destination-port 80\n",
            "huawei_usg", "hillstone",
        )
        assert "service HTTP tcp 80" in result, \
            f"Expected Hillstone service format: {result}"

    def test_huawei_usg_service_udp_auto(self):
        result = RuleBasedTranslator().translate(
            "ip service-set DNS type object\n service 0 protocol udp destination-port 53\n",
            "huawei_usg", "hillstone",
        )
        assert "service DNS udp 53" in result, \
            f"Expected Hillstone service format: {result}"

    def test_huawei_usg_service_icmp_auto(self):
        result = RuleBasedTranslator().translate(
            "ip service-set PING type object\n service 0 protocol icmp\n",
            "huawei_usg", "hillstone",
        )
        assert "service PING icmp" in result, \
            f"Expected Hillstone ICMP service: {result}"

    def test_huawei_usg_service_range_manual_review(self):
        result = RuleBasedTranslator().translate(
            "ip service-set HTTPS type object\n service 0 protocol tcp destination-port 443-443\n",
            "huawei_usg", "hillstone",
        )
        assert "MANUAL_REVIEW" in result, \
            "Service range should be MANUAL_REVIEW"

    def test_huawei_usg_service_source_port_manual_review(self):
        result = RuleBasedTranslator().translate(
            "ip service-set HTTP type object\n service 0 protocol tcp source-port 1024 destination-port 80\n",
            "huawei_usg", "hillstone",
        )
        assert "MANUAL_REVIEW" in result, \
            "Source-port should be MANUAL_REVIEW"


class TestHillstoneToHuaweiUsgService:
    """Hillstone service -> Huawei USG service-set"""

    def test_hillstone_service_tcp_auto(self):
        result = RuleBasedTranslator().translate(
            "service HTTP tcp 80\n",
            "hillstone", "huawei_usg",
        )
        assert "ip service-set HTTP type object" in result, \
            f"Expected Huawei USG service-set format: {result}"
        assert "protocol tcp" in result or "protocol 6" in result, \
            f"Expected TCP: {result}"
        assert "destination-port 80" in result or "80" in result, \
            f"Expected port 80: {result}"

    def test_hillstone_service_udp_auto(self):
        result = RuleBasedTranslator().translate(
            "service DNS udp 53\n",
            "hillstone", "huawei_usg",
        )
        assert "ip service-set DNS type object" in result, \
            f"Expected service-set: {result}"
        assert "protocol udp" in result or "protocol 17" in result, \
            f"Expected UDP: {result}"

    def test_hillstone_service_icmp_auto(self):
        result = RuleBasedTranslator().translate(
            "service PING icmp\n",
            "hillstone", "huawei_usg",
        )
        assert "ip service-set PING type object" in result, \
            f"Expected service-set: {result}"
        assert "protocol icmp" in result or "protocol 1" in result, \
            f"Expected ICMP: {result}"

    def test_hillstone_service_range_manual_review(self):
        result = RuleBasedTranslator().translate(
            "service HTTPS tcp 443-443\n",
            "hillstone", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in result, \
            "Port range should be MANUAL_REVIEW"

    def test_hillstone_service_source_port_manual_review(self):
        result = RuleBasedTranslator().translate(
            "service HTTP tcp 1024 80\n",
            "hillstone", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in result, \
            "Source-port should be MANUAL_REVIEW"


class TestHillstoneToTopsecService:
    """Hillstone service -> Topsec service"""

    def test_hillstone_service_tcp_auto(self):
        result = RuleBasedTranslator().translate(
            "service HTTP tcp 80\n",
            "hillstone", "topsec",
        )
        assert "service HTTP protocol tcp destination-port 80" in result, \
            f"Expected Topsec service format: {result}"

    def test_hillstone_service_udp_auto(self):
        result = RuleBasedTranslator().translate(
            "service DNS udp 53\n",
            "hillstone", "topsec",
        )
        assert "service DNS protocol udp destination-port 53" in result, \
            f"Expected Topsec format: {result}"

    def test_hillstone_service_icmp_auto(self):
        result = RuleBasedTranslator().translate(
            "service PING icmp\n",
            "hillstone", "topsec",
        )
        assert "service PING protocol icmp" in result, \
            f"Expected Topsec ICMP format: {result}"

    def test_hillstone_service_range_manual_review(self):
        result = RuleBasedTranslator().translate(
            "service HTTPS tcp 443-443\n",
            "hillstone", "topsec",
        )
        assert "MANUAL_REVIEW" in result, \
            "Port range should be MANUAL_REVIEW"

    def test_hillstone_service_multi_port_manual_review(self):
        result = RuleBasedTranslator().translate(
            "service HTTP tcp 80,443\n",
            "hillstone", "topsec",
        )
        assert "MANUAL_REVIEW" in result, \
            "Multi-port should be MANUAL_REVIEW"


class TestTopsecToHillstoneService:
    """Topsec service -> Hillstone service"""

    def test_topsec_service_tcp_to_hillstone(self):
        result = RuleBasedTranslator().translate(
            "service HTTP protocol tcp destination-port 80\n",
            "topsec", "hillstone",
        )
        assert "service HTTP tcp 80" in result, \
            f"Expected Hillstone format: {result}"

    def test_topsec_service_udp_to_hillstone(self):
        result = RuleBasedTranslator().translate(
            "service DNS protocol udp destination-port 53\n",
            "topsec", "hillstone",
        )
        assert "service DNS udp 53" in result, \
            f"Expected Hillstone format: {result}"

    def test_topsec_service_icmp_to_hillstone(self):
        result = RuleBasedTranslator().translate(
            "service PING protocol icmp\n",
            "topsec", "hillstone",
        )
        assert "service PING icmp" in result, \
            f"Expected Hillstone format: {result}"

    def test_topsec_service_multi_port_manual_review(self):
        result = RuleBasedTranslator().translate(
            "service HTTP protocol tcp destination-port 80,443\n",
            "topsec", "hillstone",
        )
        assert "MANUAL_REVIEW" in result, \
            "Multi-port should be MANUAL_REVIEW"


class TestServiceObjectSecretNoLeak:
    """Service objects should not contain secrets"""

    def test_service_name_not_secret(self):
        result = RuleBasedTranslator().translate(
            "service HTTP protocol tcp destination-port 80\n",
            "topsec", "huawei_usg",
        )
        executable = "\n".join(_executable_lines(result))
        assert "secret" not in executable.lower()
        assert "password" not in executable.lower()
