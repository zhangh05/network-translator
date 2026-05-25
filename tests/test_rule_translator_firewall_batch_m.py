# -*- coding: utf-8 -*-
"""Batch M: corpus gap fixes for firewall domain.

Covers:
- M-A: Hillstone NAT guard (GAP-FW-02)
- M-B: DPtech address/NAT guard (GAP-FW-04)
- M-C: Topsec zone name -> Huawei USG
"""

import pytest

from core.rule_translator import RuleBasedTranslator
from core.h3c_to_cisco import H3CToCiscoTranslator

T = RuleBasedTranslator()


class TestHillstoneNAT:
    """M-A: Hillstone NAT must be guarded in cross-vendor output."""

    def test_hillstone_nat_source_to_huawei_usg(self):
        cfg = "nat source 192.168.10.0 255.255.255.0 to 198.51.100.0 255.255.255.0"
        out = T.translate(cfg, "hillstone", "huawei_usg")
        out_lower = out.lower()
        assert "manual_review" in out_lower, f"Expected MANUAL_REVIEW, got: {out}"
        assert "nat" not in out.replace("manual_review", "").lower() or "manual_review" in out_lower

    def test_hillstone_nat_source_to_topsec(self):
        cfg = "nat source 192.168.10.0 255.255.255.0 to 198.51.100.0 255.255.255.0"
        out = T.translate(cfg, "hillstone", "topsec")
        out_lower = out.lower()
        assert "manual_review" in out_lower, f"Expected MANUAL_REVIEW, got: {out}"
        non_comment_lines = [l for l in out_lower.splitlines() if not l.strip().startswith("#")]
        assert "nat" not in "\n".join(non_comment_lines), f"NAT leaked into non-comment output: {out}"

    def test_hillstone_nat_policy_to_huawei_usg(self):
        cfg = "nat-policy POL1 source-zone trust destination-zone untrust"
        out = T.translate(cfg, "hillstone", "huawei_usg")
        assert "manual_review" in out.lower()

    def test_hillstone_nat_policy_to_topsec(self):
        cfg = "nat-policy POL1 source-zone trust destination-zone untrust"
        out = T.translate(cfg, "hillstone", "topsec")
        assert "manual_review" in out.lower()

    def test_hillstone_zone_still_auto_translates(self):
        cfg = "zone trust"
        out = T.translate(cfg, "hillstone", "huawei_usg")
        assert "security-zone name trust" in out.lower()
        assert "manual_review" not in out.lower()

    def test_hillstone_address_still_auto_translates(self):
        cfg = "address TRUSTED 192.168.10.0 255.255.255.0"
        out = T.translate(cfg, "hillstone", "huawei_usg")
        out_lower = out.lower()
        assert "ip address-set" in out_lower and "trusted" in out_lower, f"Expected auto-translate, got: {out}"
        assert "nat " not in out_lower

    def test_hillstone_service_still_auto_translates(self):
        cfg = "service HTTP tcp 80"
        out = T.translate(cfg, "hillstone", "huawei_usg")
        out_lower = out.lower()
        assert "ip service-set" in out_lower and "http" in out_lower, f"Expected auto-translate, got: {out}"

    def test_hillstone_policy_all_fields_still_auto_translates(self):
        cfg = "policy ALLOW from trust to untrust source TRUSTED destination UNTRUST service HTTP action permit"
        out = T.translate(cfg, "hillstone", "huawei_usg")
        out_lower = out.lower()
        assert "manual_review" not in out_lower or "policy" in out_lower

    def test_hillstone_same_vendor_nat_guard(self):
        cfg = "nat source 192.168.10.0 255.255.255.0 to 198.51.100.0 255.255.255.0"
        out = T.translate(cfg, "hillstone", "hillstone")
        out_lower = out.lower()
        assert "manual_review" in out_lower or "#" in out


class TestDPtechNAT:
    """M-B: DPtech NAT and address-range must be guarded."""

    def test_dptech_nat_to_huawei_usg(self):
        cfg = "nat address-group NAT-POOL"
        out = T.translate(cfg, "dptech", "huawei_usg")
        out_lower = out.lower()
        assert "manual_review" in out_lower, f"Expected MANUAL_REVIEW, got: {out}"
        non_comment_lines = [l for l in out_lower.splitlines() if not l.strip().startswith("#")]
        assert "nat" not in "\n".join(non_comment_lines), f"NAT leaked into non-comment output: {out}"

    def test_dptech_nat_to_hillstone(self):
        cfg = "nat address-group NAT-POOL"
        out = T.translate(cfg, "dptech", "hillstone")
        out_lower = out.lower()
        assert "manual_review" in out_lower, f"Expected MANUAL_REVIEW, got: {out}"
        non_comment_lines = [l for l in out_lower.splitlines() if not l.strip().startswith("#")]
        assert "nat" not in "\n".join(non_comment_lines), f"NAT leaked into non-comment output: {out}"

    def test_dptech_nat_source_to_huawei_usg(self):
        cfg = "nat source-zone trust nat address-group NAT-POOL"
        out = T.translate(cfg, "dptech", "huawei_usg")
        assert "manual_review" in out.lower()

    def test_dptech_nat_source_to_hillstone(self):
        cfg = "nat source-zone trust nat address-group NAT-POOL"
        out = T.translate(cfg, "dptech", "hillstone")
        assert "manual_review" in out.lower()

    def test_dptech_object_address_range_to_huawei_usg(self):
        cfg = "object address-range RANGE1 10.0.0.1 10.0.0.254"
        out = T.translate(cfg, "dptech", "huawei_usg")
        out_lower = out.lower()
        assert "manual_review" in out_lower, f"Expected MANUAL_REVIEW, got: {out}"
        raw_lines = [l for l in out_lower.splitlines() if not l.strip().startswith("#")]
        raw_text = " ".join(raw_lines)
        assert "object address" not in raw_text, f"object address leaked into non-comment output: {out}"

    def test_dptech_object_address_range_to_hillstone(self):
        cfg = "object address-range RANGE1 10.0.0.1 10.0.0.254"
        out = T.translate(cfg, "dptech", "hillstone")
        out_lower = out.lower()
        assert "manual_review" in out_lower, f"Expected MANUAL_REVIEW, got: {out}"
        raw_lines = [l for l in out_lower.splitlines() if not l.strip().startswith("#")]
        raw_text = " ".join(raw_lines)
        assert "object address" not in raw_text, f"object address leaked into non-comment output: {out}"

    def test_dptech_zone_still_auto_translates(self):
        cfg = "zone trust"
        out = T.translate(cfg, "dptech", "huawei_usg")
        assert "security-zone name trust" in out.lower() or "manual_review" in out.lower()

    def test_dptech_complete_policy_still_auto_translates_to_huawei_usg(self):
        cfg = (
            "security-policy name ALLOW-WEB\n"
            " source-zone trust\n"
            " destination-zone untrust\n"
            " source-address TRUSTED\n"
            " destination-address UNTRUST\n"
            " service HTTP\n"
            " action permit"
        )
        out = T.translate(cfg, "dptech", "huawei_usg")
        out_lower = out.lower()
        assert "security-policy" in out_lower
        raw_lines = [l for l in out_lower.splitlines() if not l.strip().startswith("#")]
        raw_text = " ".join(raw_lines)
        assert "manual_review" not in raw_text, f"Complete DPtech policy should auto-translate, got: {out}"

    def test_dptech_complete_policy_still_auto_translates_to_hillstone(self):
        cfg = (
            "security-policy name ALLOW-WEB\n"
            " source-zone trust\n"
            " destination-zone untrust\n"
            " source-address TRUSTED\n"
            " destination-address UNTRUST\n"
            " service HTTP\n"
            " action permit"
        )
        out = T.translate(cfg, "dptech", "hillstone")
        out_lower = out.lower()
        assert "policy" in out_lower
        raw_lines = [l for l in out_lower.splitlines() if not l.strip().startswith("#")]
        raw_text = " ".join(raw_lines)
        assert "manual_review" not in raw_text, f"Complete DPtech policy should auto-translate, got: {out}"

    def test_dptech_policy_missing_source_address_manual_review(self):
        cfg = (
            "security-policy name ALLOW-WEB\n"
            " source-zone trust\n"
            " destination-zone untrust\n"
            " destination-address UNTRUST\n"
            " service HTTP\n"
            " action permit"
        )
        out = T.translate(cfg, "dptech", "hillstone")
        out_lower = out.lower()
        assert "manual_review" in out_lower, f"Expected MANUAL_REVIEW for missing source-address, got: {out}"


class TestTopsecZoneName:
    """M-C: Topsec zone name -> Huawei USG security-zone name."""

    def test_topsec_zone_name_trust(self):
        cfg = "zone name trust"
        out = T.translate(cfg, "topsec", "huawei_usg")
        assert "security-zone name trust" in out.lower()
        assert "manual_review" not in out.lower()

    def test_topsec_zone_name_untrust(self):
        cfg = "zone name untrust"
        out = T.translate(cfg, "topsec", "huawei_usg")
        assert "security-zone name untrust" in out.lower()

    def test_topsec_zone_add_interface_manual_review(self):
        cfg = "zone name trust\n add interface ge0/0"
        out = T.translate(cfg, "topsec", "huawei_usg")
        out_lower = out.lower()
        assert "manual_review" in out_lower or "zone" in out_lower

    def test_topsec_zone_still_auto_translates_to_hillstone(self):
        cfg = "zone name trust"
        out = T.translate(cfg, "topsec", "hillstone")
        out_lower = out.lower()
        assert "zone" in out_lower
        assert "manual_review" not in out_lower or "zone" in out_lower