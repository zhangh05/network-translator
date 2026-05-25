# -*- coding: utf-8 -*-
"""NAT manual review tests for Batch I-F.

Verifies that NAT commands from all firewall vendors remain MANUAL_REVIEW
and that no NAT source syntax leaks through.
"""

import pytest
from core.rule_translator import RuleBasedTranslator


def _executable_lines(text: str):
    return [
        l for l in text.split("\n")
        if l.strip() and not l.strip().startswith("#") and not l.strip().startswith("!")
    ]


def _has_nat_source_syntax(result: str, source_vendor: str) -> bool:
    """Check if result contains NAT source syntax from source vendor."""
    nat_keywords = [
        "nat ", "source-nat", "destination-nat", "nat-policy",
        "nat pool", "ip nat", "nat inside", "nat outside",
    ]
    source_vendor = source_vendor.lower()
    if source_vendor == "cisco":
        nat_keywords += ["inside source", "outside source"]
    if source_vendor == "huawei":
        nat_keywords += ["nat-policy", "nat address-group"]
    if source_vendor == "hillstone":
        nat_keywords += ["source-nat", "nat POLICY"]
    if source_vendor == "topsec":
        nat_keywords += ["nat policy", "source-nat"]
    if source_vendor == "dptech":
        nat_keywords += ["nat-policy"]

    executable = "\n".join(_executable_lines(result))
    return any(kw in executable for kw in nat_keywords)


class TestCiscoNATManualReview:
    """Cisco NAT -> all targets must be MANUAL_REVIEW"""

    def test_cisco_ip_nat_inside_source(self):
        result = RuleBasedTranslator().translate(
            "ip nat inside source static 10.0.0.1 100.0.0.1\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in result, \
            "Cisco NAT should be MANUAL_REVIEW"

    def test_cisco_ip_nat_outside_source(self):
        result = RuleBasedTranslator().translate(
            "ip nat outside source static 10.0.0.1 100.0.0.1\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in result, \
            "Cisco NAT should be MANUAL_REVIEW"

    def test_cisco_ip_nat_pool(self):
        result = RuleBasedTranslator().translate(
            "ip nat pool POOL-1 100.0.0.1 100.0.0.10 netmask 255.255.255.0\n",
            "cisco", "huawei",
        )
        assert "MANUAL_REVIEW" in result, \
            "Cisco NAT pool should be MANUAL_REVIEW"

    def test_cisco_no_nat_syntax_leaks_to_huawei(self):
        result = RuleBasedTranslator().translate(
            "ip nat inside source list 100 interface GigabitEthernet0/0/1 overload\n",
            "cisco", "huawei",
        )
        assert not _has_nat_source_syntax(result, "cisco"), \
            "Cisco NAT source syntax should not appear in Huawei output"

    def test_cisco_nat_to_huaweiusg_manual_review(self):
        result = RuleBasedTranslator().translate(
            "ip nat inside source static tcp 10.0.0.1 80 100.0.0.1 8080\n",
            "cisco", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in result, \
            "Cisco NAT should be MANUAL_REVIEW for Huawei USG"


class TestHuaweiNATManualReview:
    """Huawei NAT -> all targets must be MANUAL_REVIEW"""

    def test_huawei_nat_policy(self):
        result = RuleBasedTranslator().translate(
            "nat-policy\n",
            "huawei", "cisco",
        )
        assert "MANUAL_REVIEW" in result, \
            "Huawei NAT policy should be MANUAL_REVIEW"

    def test_huawei_nat_address_group(self):
        result = RuleBasedTranslator().translate(
            "nat address-group AG-1\n",
            "huawei", "cisco",
        )
        assert "MANUAL_REVIEW" in result, \
            "Huawei NAT address-group should be MANUAL_REVIEW"

    def test_huawei_nat_policy_rule(self):
        result = RuleBasedTranslator().translate(
            "nat-policy rule NAME\n",
            "huawei", "cisco",
        )
        assert "MANUAL_REVIEW" in result, \
            "Huawei NAT policy rule should be MANUAL_REVIEW"


class TestHillstoneNATManualReview:
    """Hillstone NAT -> all targets must be MANUAL_REVIEW"""

    def test_hillstone_nat(self):
        result = RuleBasedTranslator().translate(
            "nat POLICY-1\n",
            "hillstone", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in result, \
            "Hillstone NAT should be MANUAL_REVIEW"

    def test_hillstone_source_nat(self):
        result = RuleBasedTranslator().translate(
            "source-nat POOL-1\n",
            "hillstone", "topsec",
        )
        assert "MANUAL_REVIEW" in result, \
            "Hillstone source-nat should be MANUAL_REVIEW"


class TestTopsecNATManualReview:
    """Topsec NAT -> all targets must be MANUAL_REVIEW"""

    def test_topsec_nat_policy(self):
        result = RuleBasedTranslator().translate(
            "nat policy NAT-POOL\n",
            "topsec", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in result, \
            "Topsec NAT policy should be MANUAL_REVIEW"

    def test_topsec_source_nat(self):
        result = RuleBasedTranslator().translate(
            "source-nat POLICY1\n",
            "topsec", "hillstone",
        )
        assert "MANUAL_REVIEW" in result, \
            "Topsec source-nat should be MANUAL_REVIEW"


class TestDPtechNATManualReview:
    """DPtech NAT -> all targets must be MANUAL_REVIEW"""

    def test_dptech_nat_policy(self):
        result = RuleBasedTranslator().translate(
            "nat-policy NAME\n",
            "dptech", "huawei_usg",
        )
        assert "MANUAL_REVIEW" in result, \
            "DPtech NAT policy should be MANUAL_REVIEW"


class TestNATNoSourceSyntaxLeaks:
    """NAT commands should not leave source vendor syntax in target output"""

    @pytest.mark.parametrize("fv,tv", [
        ("cisco", "huawei"),
        ("cisco", "huawei_usg"),
        ("cisco", "hillstone"),
        ("cisco", "topsec"),
        ("huawei", "cisco"),
        ("huawei", "huawei_usg"),
        ("huawei", "hillstone"),
        ("hillstone", "huawei_usg"),
        ("hillstone", "topsec"),
        ("topsec", "huawei_usg"),
        ("topsec", "hillstone"),
    ])
    def test_nat_no_cross_leak(self, fv, tv):
        result = RuleBasedTranslator().translate(
            "ip nat inside source static 10.0.0.1 100.0.0.1\n"
            if fv == "cisco" else
            "nat policy NAT-POOL\n"
            if fv in ("huawei", "topsec", "dptech") else
            "nat POLICY-1\n",
            fv, tv,
        )
        assert not _has_nat_source_syntax(result, fv), \
            f"NAT source syntax from {fv} should not appear in {tv} output"
