from __future__ import annotations

from core.domain import DeviceDomain
from core.ir_models.enums import IRRiskLevel
from core.vendor import init_profiles, get_profile
from core.vendor.base import (
    ForbiddenPattern,
    VendorPlatformProfile,
)
from core.vendor.enums import ForbiddenPatternCategory
from core.validator.residue_validator import ResidueValidator


class TestResidueValidator:
    def setup_method(self):
        init_profiles()

    # --- Cisco profile: detect H3C residuals in Cisco output ---

    def test_cisco_detects_h3c_residual_in_executable(self):
        cisco = get_profile("cisco_ios_xe")
        validator = ResidueValidator(profile=cisco)

        config = """\
hostname Router
!
interface Vlan-interface 100
 ip address 10.0.0.1 255.255.255.0
!
ip route-static 0.0.0.0 0.0.0.0 10.0.0.254
"""
        issues = validator.validate(config)
        assert len(issues) >= 2
        vlan_if = [i for i in issues if "Vlan-interface" in i.message]
        assert len(vlan_if) >= 1
        assert vlan_if[0].severity == IRRiskLevel.HIGH
        route = [i for i in issues if "ip route-static" in i.message]
        assert len(route) >= 1
        assert route[0].severity == IRRiskLevel.HIGH

    def test_cisco_comment_h3c_residual_is_low(self):
        cisco = get_profile("cisco_ios_xe")
        validator = ResidueValidator(profile=cisco)

        config = """\
hostname Router
!
! Original: interface Vlan-interface 100
! Original: ip route-static 0.0.0.0 0.0.0.0 10.0.0.254
!
interface Vlan100
 ip address 10.0.0.1 255.255.255.0
"""
        issues = validator.validate(config)
        for issue in issues:
            assert issue.severity != IRRiskLevel.HIGH, (
                f"Comment residue should not be HIGH: {issue.message}"
            )
            assert issue.severity == IRRiskLevel.LOW

    def test_cisco_clean_output_no_residue(self):
        cisco = get_profile("cisco_ios_xe")
        validator = ResidueValidator(profile=cisco)

        config = """\
hostname Router
!
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 10
!
ip route 0.0.0.0 0.0.0.0 10.0.0.254
"""
        issues = validator.validate(config)
        assert len(issues) == 0

    # --- Huawei VRP profile: detect Cisco residuals in Huawei output ---

    def test_huawei_detects_cisco_residual_in_executable(self):
        huawei = get_profile("huawei_vrp")
        validator = ResidueValidator(profile=huawei)

        config = """\
#
sysname Router
#
interface Vlan10
 ip address 10.0.0.1 255.255.255.0
#
interface Port-channel1
 port link-type trunk
"""
        issues = validator.validate(config)
        cisco_ifaces = [i for i in issues if "interface Vlan" in i.message]
        assert len(cisco_ifaces) >= 1, (
            f"Should detect 'interface Vlan' as Cisco residual, got: "
            f"{[i.message for i in issues]}"
        )
        assert cisco_ifaces[0].severity == IRRiskLevel.MEDIUM

    def test_huawei_comment_cisco_residual_is_low(self):
        huawei = get_profile("huawei_vrp")
        validator = ResidueValidator(profile=huawei, comment_char="#")

        config = """\
#
sysname Router
# Original: hostname Router
# Original: interface Port-channel1
#
interface Eth-Trunk1
 port link-type trunk
"""
        issues = validator.validate(config)
        for issue in issues:
            assert issue.severity == IRRiskLevel.LOW, (
                f"Comment content should be LOW: {issue.message}"
            )

    def test_huawei_custom_comment_char_via_profile(self):
        """Huawei uses '#' as comment char, not '!'."""
        huawei = get_profile("huawei_vrp")
        assert huawei.comment_char == "#"
        validator = ResidueValidator(profile=huawei)

        config = "# hostname Router\n"
        issues = validator.validate(config)
        # hostname is a Cisco residual pattern for H3C, not for Huawei
        # Just verify comment_char is picked up from profile
        assert validator.comment_char == "#"

    # --- Firewall profile: detect residuals in Huawei USG / Topsec output ---

    def test_firewall_profile_detects_residual(self):
        usg = get_profile("huawei_usg")
        validator = ResidueValidator(profile=usg)

        config = "#\n# sysname FW01\nswitchport mode access\n#\n"
        issues = validator.validate(config)
        switchport_issues = [i for i in issues if "switchport" in i.message]
        assert len(switchport_issues) >= 1
        assert switchport_issues[0].severity == IRRiskLevel.HIGH

    # --- Cross-platform: H3C profile detects Cisco residuals ---

    def test_h3c_detects_cisco_residual(self):
        h3c = get_profile("h3c_comware")
        validator = ResidueValidator(profile=h3c)

        config = """\
sysname Router
#
switchport mode access
#
hostname BadRouter
"""
        issues = validator.validate(config)
        switchport = [i for i in issues if "switchport" in i.message]
        assert len(switchport) >= 1
        assert switchport[0].severity == IRRiskLevel.HIGH

    # --- Custom profile test ---

    def test_custom_profile_residual(self):
        profile = VendorPlatformProfile(
            key="test_fw",
            vendor="test",
            platform="fw",
            display_name="Test FW",
            device_family="firewall",
            supported_domains=[DeviceDomain.FIREWALL],
            comment_char="#",
            forbidden_patterns=[
                ForbiddenPattern(
                    pattern=r"(?i)set\s+zone\s+",
                    severity=IRRiskLevel.HIGH,
                    category=ForbiddenPatternCategory.RESIDUAL_SYNTAX,
                    message="'set zone' is Juniper syntax, not valid here",
                ),
            ],
        )
        validator = ResidueValidator(profile=profile)
        issues = validator.validate("set zone untrust\n")
        assert len(issues) == 1
        assert issues[0].severity == IRRiskLevel.HIGH

    def test_custom_profile_comment_is_low(self):
        profile = VendorPlatformProfile(
            key="test_fw",
            vendor="test",
            platform="fw",
            display_name="Test FW",
            device_family="firewall",
            supported_domains=[DeviceDomain.FIREWALL],
            comment_char="#",
            forbidden_patterns=[
                ForbiddenPattern(
                    pattern=r"(?i)set\s+zone\s+",
                    severity=IRRiskLevel.HIGH,
                    category=ForbiddenPatternCategory.RESIDUAL_SYNTAX,
                    message="'set zone' is Juniper syntax",
                ),
            ],
        )
        validator = ResidueValidator(profile=profile)
        issues = validator.validate("# set zone untrust (original config)\n")
        assert len(issues) == 1
        assert issues[0].severity == IRRiskLevel.LOW

    def test_residue_span_is_target_span(self):
        cisco = get_profile("cisco_ios_xe")
        validator = ResidueValidator(profile=cisco)
        issues = validator.validate("sysname BadRouter\n")
        assert issues[0].target_span is not None
        assert issues[0].target_span.start_line == 1
        assert issues[0].source_text == "sysname BadRouter"

    def test_suggestion_included(self):
        profile = VendorPlatformProfile(
            key="test",
            vendor="t",
            platform="t",
            display_name="T",
            device_family="switch",
            supported_domains=[DeviceDomain.SWITCH],
            comment_char="!",
            forbidden_patterns=[
                ForbiddenPattern(
                    pattern=r"(?i)undo\s+",
                    severity=IRRiskLevel.HIGH,
                    category=ForbiddenPatternCategory.RESIDUAL_SYNTAX,
                    message="Use 'no' instead of 'undo'",
                    suggested_action="Replace 'undo' with 'no'",
                ),
            ],
        )
        validator = ResidueValidator(profile=profile)
        issues = validator.validate("undo vlan 10\n")
        assert issues[0].suggestion == "Replace 'undo' with 'no'"
