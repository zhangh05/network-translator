import pytest
from core.vendor import init_profiles, get_profile, list_profiles
from core.domain import DeviceDomain


def setup_module():
    init_profiles()


class TestRegistry:
    def test_all_8_profiles_registered(self):
        profiles = list_profiles()
        assert len(profiles) == 8

    def test_cisco_ios_xe_present(self):
        p = get_profile("cisco_ios_xe")
        assert p is not None
        assert p.vendor == "cisco"

    def test_h3c_comware_present(self):
        p = get_profile("h3c_comware")
        assert p is not None
        assert p.vendor == "h3c"

    def test_huawei_vrp_present(self):
        p = get_profile("huawei_vrp")
        assert p is not None
        assert p.vendor == "huawei"

    def test_huawei_usg_present(self):
        p = get_profile("huawei_usg")
        assert p is not None
        assert p.platform == "usg"

    def test_ruijie_rgos_present(self):
        p = get_profile("ruijie_rgos")
        assert p is not None
        assert "rg" in p.platform

    def test_hillstone_present(self):
        p = get_profile("hillstone_stoneos")
        assert p is not None
        assert "stone" in p.platform

    def test_topsec_present(self):
        p = get_profile("topsec_tos")
        assert p is not None
        assert p.vendor == "topsec"

    def test_dptech_present(self):
        p = get_profile("dptech_fw")
        assert p is not None
        assert p.vendor == "dptech"


class TestProfileDomains:
    def test_cisco_switch_router(self):
        p = get_profile("cisco_ios_xe")
        assert DeviceDomain.SWITCH in p.supported_domains
        assert DeviceDomain.ROUTER in p.supported_domains

    def test_h3c_switch_router(self):
        p = get_profile("h3c_comware")
        assert DeviceDomain.SWITCH in p.supported_domains
        assert DeviceDomain.ROUTER in p.supported_domains

    def test_huawei_vrp_switch_router(self):
        p = get_profile("huawei_vrp")
        assert DeviceDomain.SWITCH in p.supported_domains
        assert DeviceDomain.ROUTER in p.supported_domains
        assert DeviceDomain.FIREWALL not in p.supported_domains

    def test_huawei_usg_firewall_only(self):
        p = get_profile("huawei_usg")
        assert DeviceDomain.FIREWALL in p.supported_domains
        assert DeviceDomain.SWITCH not in p.supported_domains
        assert DeviceDomain.ROUTER not in p.supported_domains

    def test_hillstone_firewall_only(self):
        p = get_profile("hillstone_stoneos")
        assert DeviceDomain.FIREWALL in p.supported_domains
        assert DeviceDomain.SWITCH not in p.supported_domains

    def test_topsec_firewall_only(self):
        p = get_profile("topsec_tos")
        assert DeviceDomain.FIREWALL in p.supported_domains
        assert DeviceDomain.SWITCH not in p.supported_domains

    def test_dptech_firewall_only(self):
        p = get_profile("dptech_fw")
        assert DeviceDomain.FIREWALL in p.supported_domains
        assert DeviceDomain.SWITCH not in p.supported_domains


class TestProfileCapabilities:
    def test_cisco_has_switch_capabilities(self):
        p = get_profile("cisco_ios_xe")
        caps = p.capabilities.get(DeviceDomain.SWITCH, {})
        assert len(caps) > 0
        from core.domain import FeatureKey
        assert FeatureKey.VLAN in caps

    def test_cisco_has_router_capabilities(self):
        p = get_profile("cisco_ios_xe")
        caps = p.capabilities.get(DeviceDomain.ROUTER, {})
        assert len(caps) > 0
        from core.domain import FeatureKey
        assert FeatureKey.OSPF in caps

    def test_hillstone_has_firewall_capabilities(self):
        p = get_profile("hillstone_stoneos")
        caps = p.capabilities.get(DeviceDomain.FIREWALL, {})
        assert len(caps) > 0
        from core.domain import FeatureKey
        assert FeatureKey.ZONE in caps

    def test_huawei_usg_no_switch_capabilities(self):
        p = get_profile("huawei_usg")
        assert DeviceDomain.SWITCH not in p.capabilities

    def test_topsec_no_switch_capabilities(self):
        p = get_profile("topsec_tos")
        assert DeviceDomain.SWITCH not in p.capabilities

    def test_dptech_has_firewall_capabilities(self):
        p = get_profile("dptech_fw")
        caps = p.capabilities.get(DeviceDomain.FIREWALL, {})
        assert len(caps) > 0


class TestProfileForbiddenPatterns:
    def test_cisco_has_forbidden_patterns(self):
        p = get_profile("cisco_ios_xe")
        assert len(p.forbidden_patterns) > 0
        # Should detect H3C residual commands
        patterns = [fp.pattern for fp in p.forbidden_patterns]
        assert any("undo" in pat for pat in patterns)

    def test_h3c_has_forbidden_patterns(self):
        p = get_profile("h3c_comware")
        assert len(p.forbidden_patterns) > 0
        # Should detect Cisco residual commands
        patterns = [fp.pattern for fp in p.forbidden_patterns]
        assert any("switchport" in pat for pat in patterns)

    def test_all_profiles_have_some_forbidden_patterns(self):
        for p in list_profiles():
            assert len(p.forbidden_patterns) > 0, f"{p.key} has no forbidden patterns"


class TestProfileSignatures:
    def test_all_profiles_have_signatures(self):
        for p in list_profiles():
            assert len(p.signatures) > 0, f"{p.key} has no signatures"


class TestProfileDisplayNames:
    def test_display_names(self):
        assert get_profile("cisco_ios_xe").display_name == "Cisco IOS-XE"
        assert get_profile("h3c_comware").display_name == "H3C Comware"
        assert get_profile("huawei_vrp").display_name == "Huawei VRP"
        assert get_profile("huawei_usg").display_name == "Huawei USG"
        assert get_profile("hillstone_stoneos").display_name == "Hillstone StoneOS"


class TestProfileCommentChars:
    def test_cisco_exclamation(self):
        assert get_profile("cisco_ios_xe").comment_char == "!"

    def test_huawei_hash(self):
        assert get_profile("huawei_vrp").comment_char == "#"
        assert get_profile("huawei_usg").comment_char == "#"
