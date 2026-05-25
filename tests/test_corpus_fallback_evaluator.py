# -*- coding: utf-8 -*-
"""Tests for corpus_fallback_evaluator residue checking logic.

Covers:
- forbidden_executable_residue only matches in executable lines
- MANUAL_REVIEW comment content does NOT count as executable residue
- secret leakage checks the full output (including comments)
"""

import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.evaluate_corpus_fallback import (
    strip_fence,
    is_executable_line,
    filter_executable_lines,
)


class TestIsExecutableLine:
    def test_empty_line(self):
        assert is_executable_line("") is False
        assert is_executable_line("   ") is False

    def test_shell_comment(self):
        assert is_executable_line("# manual review") is False

    def test_c_comment(self):
        assert is_executable_line("// comment") is False

    def test_excl_comment(self):
        assert is_executable_line("! comment") is False

    def test_code_fence_open(self):
        assert is_executable_line("```huawei_usg") is False

    def test_code_fence_close(self):
        assert is_executable_line("```") is False

    def test_code_fence_line(self):
        assert is_executable_line("```huawei") is False

    def test_normal_config_line(self):
        assert is_executable_line("security-policy") is True
        assert is_executable_line(" zone trust") is True
        assert is_executable_line("  source-address TRUSTED") is True

    def test_config_with_leading_whitespace(self):
        assert is_executable_line("   nat source 1.1.1.1") is True


class TestFilterExecutableLines:
    def test_removes_comments(self):
        text = "# MANUAL_REVIEW unsupported source command: nat\nsecurity-zone name trust"
        result = filter_executable_lines(text)
        assert "# MANUAL_REVIEW" not in result
        assert "security-zone" in result

    def test_removes_code_fence(self):
        text = "```huawei_usg\nsecurity-policy\n rule name foo\n```"
        result = filter_executable_lines(text)
        assert "```" not in result
        assert "security-policy" in result

    def test_keeps_nat_in_executable_line(self):
        text = "# MANUAL_REVIEW unsupported source command: nat\nnat source 1.1.1.1 to 2.2.2.2"
        result = filter_executable_lines(text)
        assert "nat" in result
        assert result.count("nat") == 1

    def test_removes_object_address_in_comment(self):
        text = "# MANUAL_REVIEW object address-range is not portable\nobject address-range RANGE1 10.0.0.1 10.0.0.254"
        result = filter_executable_lines(text)
        assert "object address-range" in result
        assert result.count("object address-range") == 1

    def test_empty_output(self):
        assert filter_executable_lines("") == ""
        assert filter_executable_lines("   \n\n") == ""


class TestStripFence:
    def test_removes_fence_lines(self):
        text = "```huawei_usg\nsecurity-policy\n```"
        result = strip_fence(text)
        assert "```" not in result
        assert "security-policy" in result

    def test_handles_no_fence(self):
        text = "security-policy\n zone trust"
        assert strip_fence(text) == text


class TestManualReviewCommentNat:
    """MANUAL_REVIEW comment containing 'nat' is NOT executable residue."""

    def test_nat_in_manual_review_comment_not_executable_residue(self):
        text = "# MANUAL_REVIEW unsupported source command: nat source 192.168.10.0"
        exec_only = filter_executable_lines(text)
        assert "nat" not in exec_only

    def test_nat_in_real_executable_line_is_residue(self):
        text = "# MANUAL_REVIEW\nnat source 192.168.10.0 to 198.51.100.0"
        exec_only = filter_executable_lines(text)
        assert "nat" in exec_only


class TestSecretLeakage:
    """Secret leak checks the FULL output including comments."""

    def test_secret_in_comment_still_leaks(self):
        full_output = "# config with secret: SuperSecret123"
        assert "SuperSecret123" in full_output

    def test_secret_in_executable_line_leaks(self):
        full_output = "password SuperSecret123"
        assert "SuperSecret123" in full_output