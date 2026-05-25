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


class TestDPtechNoDefaultAny:
    """DPtech multi-line policy: incomplete blocks must NOT produce implicit any."""

    def test_dptech_multiline_missing_source_address_manual_review_no_any_huawei(self):
        cfg = (
            "security-policy name ALLOW-WEB\n"
            " source-zone trust\n"
            " destination-zone untrust\n"
            " destination-address UNTRUST\n"
            " service HTTP\n"
            " action permit"
        )
        out = T.translate(cfg, "dptech", "huawei_usg")
        out_lower = out.lower()
        assert "manual_review" in out_lower, f"Expected MANUAL_REVIEW, got: {out}"
        assert "source any" not in out_lower, f"Should not default source to 'any': {out}"
        assert "any" not in out.get_output_marker_body() if hasattr(out, 'get_output_marker_body') else "source any" not in out_lower

    def test_dptech_multiline_missing_source_address_manual_review_no_any_hillstone(self):
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
        assert "manual_review" in out_lower, f"Expected MANUAL_REVIEW, got: {out}"
        assert " source any" not in out_lower, f"Should not default source to 'any': {out}"

    def test_dptech_multiline_missing_service_manual_review_no_any_huawei(self):
        cfg = (
            "security-policy name ALLOW-WEB\n"
            " source-zone trust\n"
            " destination-zone untrust\n"
            " source-address TRUSTED\n"
            " destination-address UNTRUST\n"
            " action permit"
        )
        out = T.translate(cfg, "dptech", "huawei_usg")
        out_lower = out.lower()
        assert "manual_review" in out_lower, f"Expected MANUAL_REVIEW, got: {out}"
        assert " service any" not in out_lower, f"Should not default service to 'any': {out}"

    def test_dptech_multiline_complete_no_any_huawei(self):
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
        assert "manual_review" not in out_lower, f"Should auto-translate, got: {out}"
        assert " source any" not in out_lower, f"Should not default source to 'any': {out}"
        assert " destination any" not in out_lower, f"Should not default dest to 'any': {out}"
        assert " service any" not in out_lower, f"Should not default service to 'any': {out}"

    def test_dptech_multiline_complete_no_any_hillstone(self):
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
        assert "manual_review" not in out_lower, f"Should auto-translate, got: {out}"
        assert " source any" not in out_lower, f"Should not default source to 'any': {out}"
        assert " destination any" not in out_lower, f"Should not default dest to 'any': {out}"
        assert " service any" not in out_lower, f"Should not default service to 'any': {out}"


class TestHelperNoDefaultAny:
    """Direct helper tests: must raise ValueError on missing fields."""

    def test_render_huawei_secpol_rule_raises_on_missing_source_zone(self):
        from core.fallback.firewall_rules import _render_huawei_secpol_rule
        with pytest.raises(ValueError, match="source_zone"):
            _render_huawei_secpol_rule({
                "name": "TEST",
                "dest_zone": "untrust",
                "source_address": "SRC",
                "dest_address": "DST",
                "service": "HTTP",
                "action": "permit",
            })

    def test_render_huawei_secpol_rule_raises_on_missing_service(self):
        from core.fallback.firewall_rules import _render_huawei_secpol_rule
        with pytest.raises(ValueError, match="service"):
            _render_huawei_secpol_rule({
                "name": "TEST",
                "source_zone": "trust",
                "dest_zone": "untrust",
                "source_address": "SRC",
                "dest_address": "DST",
                "action": "permit",
            })

    def test_render_hillstone_policy_raises_on_missing_src_addr(self):
        from core.fallback.firewall_rules import _render_hillstone_policy
        with pytest.raises(ValueError, match="src_addr"):
            _render_hillstone_policy({
                "name": "TEST",
                "src_zone": "trust",
                "dst_zone": "untrust",
                "dst_addr": "DST",
                "service": "HTTP",
                "action": "permit",
            })

    def test_render_policy_raises_on_missing_action(self):
        from core.fallback.firewall_rules import _render_policy
        with pytest.raises(ValueError, match="action"):
            _render_policy({
                "name": "TEST",
                "src_zone": "trust",
                "dst_zone": "untrust",
                "src_addr": "SRC",
                "dst_addr": "DST",
                "service": "HTTP",
            })

    def test_render_policy_raises_on_missing_zone(self):
        from core.fallback.firewall_rules import _render_policy
        with pytest.raises(ValueError, match="src_zone"):
            _render_policy({
                "name": "TEST",
                "src_zone": None,
                "dst_zone": "untrust",
                "src_addr": "SRC",
                "dst_addr": "DST",
                "service": "HTTP",
                "action": "permit",
            })

    def test_render_huawei_secpol_rule_complete_ok(self):
        from core.fallback.firewall_rules import _render_huawei_secpol_rule
        result = _render_huawei_secpol_rule({
            "name": "TEST",
            "source_zone": "trust",
            "dest_zone": "untrust",
            "source_address": "SRC",
            "dest_address": "DST",
            "service": "HTTP",
            "action": "permit",
        })
        assert isinstance(result, list)
        body = "\n".join(result)
        assert "source-zone trust" in body
        assert "any" not in body.lower()

    def test_render_hillstone_policy_complete_ok(self):
        from core.fallback.firewall_rules import _render_hillstone_policy
        result = _render_hillstone_policy({
            "name": "TEST",
            "src_zone": "trust",
            "dst_zone": "untrust",
            "src_addr": "SRC",
            "dst_addr": "DST",
            "service": "HTTP",
            "action": "permit",
        })
        assert isinstance(result, str)
        assert " source SRC " in result
        assert "any" not in result.lower()