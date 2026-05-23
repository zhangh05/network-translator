from __future__ import annotations

from core.ir_models.enums import IRRiskLevel
from core.validator.syntax_validator import BasicSyntaxValidator


class TestBasicSyntaxValidator:
    def test_clean_config_no_issues(self):
        v = BasicSyntaxValidator(comment_char="!")
        config = """\
hostname MyRouter
!
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
!
interface Vlan10
 ip address 192.168.1.1 255.255.255.0
"""
        issues = v.validate(config)
        assert len(issues) == 0

    def test_invalid_ip_address(self):
        v = BasicSyntaxValidator()
        config = "ip address 10.0.0.300 255.255.255.0\n"
        issues = v.validate(config)
        assert len(issues) >= 1
        assert issues[0].severity == IRRiskLevel.HIGH
        assert "10.0.0.300" in issues[0].message

    def test_non_contiguous_subnet_mask(self):
        v = BasicSyntaxValidator()
        config = "ip address 10.0.0.1 255.255.0.255\n"
        issues = v.validate(config)
        assert len(issues) >= 1
        assert issues[0].severity == IRRiskLevel.MEDIUM
        assert "non-contiguous" in issues[0].message.lower()

    def test_vlan_id_out_of_range(self):
        v = BasicSyntaxValidator()
        config = "vlan 4095\n"
        issues = v.validate(config)
        assert len(issues) >= 1
        assert issues[0].severity == IRRiskLevel.HIGH
        assert "4095" in issues[0].message

    def test_interface_name_ok(self):
        v = BasicSyntaxValidator()
        config = "interface GigabitEthernet0/1\n"
        issues = v.validate(config)
        assert len(issues) == 0

    def test_comment_lines_skipped(self):
        v = BasicSyntaxValidator(comment_char="!")
        config = "! vlan 9999\n"
        issues = v.validate(config)
        assert len(issues) == 0

    def test_multiple_issues(self):
        v = BasicSyntaxValidator()
        config = """\
interface GigabitEthernet0/1
 ip address 10.0.0.300 255.255.0.255
 vlan 5000
"""
        issues = v.validate(config)
        assert len(issues) >= 2

    def test_empty_config(self):
        v = BasicSyntaxValidator()
        issues = v.validate("")
        assert len(issues) == 0
