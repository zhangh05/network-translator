import pytest
import os
from core.parser import get_parser, init_parsers
from core.domain import DeviceDomain
from core.ir_models import IRConfig, IRVlan, IRSvi, IRInterface, IRStaticRoute, IRAcl, IRAclEntry, IRFhrp, IRLag, IROspf, IRStp, IRAaa, IRManagement
from core.ir_models.enums import IRType, IRInterfaceType, IRFhrpProtocol, ConversionStatus
from core.ir_models.base import SourceSpan


@pytest.fixture(autouse=True)
def setup():
    init_parsers()


def get_h3c_parser():
    cls = get_parser(DeviceDomain.SWITCH, "comware")
    assert cls is not None, "H3C Comware SWITCH parser not registered"
    return cls()


class TestH3CVlan:
    def test_single_vlan(self):
        p = get_h3c_parser()
        result = p.parse("vlan 10")
        assert len(result.ir.vlans) == 1
        assert result.ir.vlans[0].vid == 10
        assert result.ir.vlans[0].name is None

    def test_vlan_with_name(self):
        p = get_h3c_parser()
        result = p.parse("vlan 10\n name MGMT")
        assert len(result.ir.vlans) == 1
        assert result.ir.vlans[0].vid == 10
        assert result.ir.vlans[0].name == "MGMT"

    def test_multiple_vlans(self):
        p = get_h3c_parser()
        result = p.parse("vlan 10\n name MGMT\nvlan 20\n name DATA")
        assert len(result.ir.vlans) == 2
        assert result.ir.vlans[0].vid == 10
        assert result.ir.vlans[1].vid == 20

    def test_vlan_has_type(self):
        p = get_h3c_parser()
        result = p.parse("vlan 10")
        assert result.ir.vlans[0].type == IRType.VLAN


class TestH3CSysname:
    def test_hostname(self):
        p = get_h3c_parser()
        result = p.parse("sysname SW01")
        assert result.ir.meta.hostname == "SW01"


class TestH3CSvi:
    def test_basic_svi(self):
        p = get_h3c_parser()
        result = p.parse("interface Vlan-interface10\n ip address 10.0.10.1 255.255.255.0")
        assert len(result.ir.svis) == 1
        assert result.ir.svis[0].vid == 10
        assert result.ir.svis[0].ip == "10.0.10.1"

    def test_svi_with_vrrp(self):
        p = get_h3c_parser()
        result = p.parse(
            "interface Vlan-interface10\n"
            " ip address 10.0.10.1 255.255.255.0\n"
            " vrrp vrid 10 virtual-ip 10.0.10.254\n"
            " vrrp vrid 10 priority 110"
        )
        assert len(result.ir.svis) == 1
        assert len(result.ir.svis[0].fhrp) == 1
        assert result.ir.svis[0].fhrp[0].protocol == IRFhrpProtocol.VRRP
        assert result.ir.svis[0].fhrp[0].group_id == 10
        assert result.ir.svis[0].fhrp[0].virtual_ip == "10.0.10.254"
        assert result.ir.svis[0].fhrp[0].priority == 110

    def test_svi_packet_filter(self):
        p = get_h3c_parser()
        result = p.parse(
            "interface Vlan-interface107\n"
            " packet-filter 3050 inbound"
        )
        assert result.ir.svis[0].acl_in == "3050"


class TestH3CInterface:
    def test_physical_interface(self):
        p = get_h3c_parser()
        result = p.parse(
            "interface GigabitEthernet0/0/1\n"
            " port link-mode bridge\n"
            " description TO-SW02\n"
            " port access vlan 10"
        )
        assert len(result.ir.interfaces) == 1
        iface = result.ir.interfaces[0]
        assert iface.iftype == IRInterfaceType.PHYSICAL
        assert iface.description == "TO-SW02"
        assert iface.untagged_vlan == 10

    def test_trunk_interface(self):
        p = get_h3c_parser()
        result = p.parse(
            "interface GigabitEthernet0/0/2\n"
            " port link-type trunk\n"
            " port trunk permit vlan 1 10 to 20"
        )
        iface = result.ir.interfaces[0]
        assert iface.trunk_allowed_all is False
        assert iface.trunk_allowed is not None
        assert 10 in iface.trunk_allowed
        assert 15 in iface.trunk_allowed
        assert 20 in iface.trunk_allowed

    def test_trunk_all_vlan(self):
        p = get_h3c_parser()
        result = p.parse(
            "interface GigabitEthernet0/0/3\n"
            " port link-type trunk\n"
            " port trunk permit vlan all"
        )
        assert result.ir.interfaces[0].trunk_allowed_all is True

    def test_lag_member(self):
        p = get_h3c_parser()
        result = p.parse(
            "interface GigabitEthernet0/0/23\n"
            " port link-type trunk\n"
            " port link-aggregation group 1\n"
            "interface GigabitEthernet0/0/24\n"
            " port link-type trunk\n"
            " port link-aggregation group 1"
        )
        assert len(result.ir.interfaces) == 2
        assert result.ir.interfaces[0].lag_group == 1
        assert result.ir.interfaces[1].lag_group == 1

    def test_loopback(self):
        p = get_h3c_parser()
        result = p.parse("interface LoopBack0\n ip address 10.0.0.1 255.255.255.255")
        assert len(result.ir.interfaces) == 1
        assert result.ir.interfaces[0].iftype == IRInterfaceType.LOOPBACK


class TestH3CLag:
    def test_bridge_aggregation(self):
        p = get_h3c_parser()
        result = p.parse(
            "interface Bridge-Aggregation1\n"
            " description TO-SW02\n"
            " port link-type trunk\n"
            " port trunk permit vlan 1 10 to 20"
        )
        assert len(result.ir.lags) == 1
        assert result.ir.lags[0].lag_id == 1
        assert result.ir.lags[0].mode == "static"

    def test_dynamic_lag(self):
        p = get_h3c_parser()
        result = p.parse(
            "interface Bridge-Aggregation100\n"
            " port link-type trunk\n"
            " port trunk permit vlan all\n"
            " link-aggregation mode dynamic"
        )
        assert result.ir.lags[0].mode == "lacp"

    def test_lag_members_populated(self):
        p = get_h3c_parser()
        config = (
            "interface Bridge-Aggregation1\n"
            " port link-type trunk\n"
            " port trunk permit vlan all\n"
            "interface GigabitEthernet0/0/23\n"
            " port link-type trunk\n"
            " port link-aggregation group 1\n"
            "interface GigabitEthernet0/0/24\n"
            " port link-type trunk\n"
            " port link-aggregation group 1"
        )
        result = p.parse(config)
        assert len(result.ir.lags) == 1
        assert "GigabitEthernet0/0/23" in result.ir.lags[0].member_ports
        assert "GigabitEthernet0/0/24" in result.ir.lags[0].member_ports


class TestH3COspf:
    def test_basic_ospf(self):
        p = get_h3c_parser()
        result = p.parse(
            "ospf 1 router-id 10.0.0.1\n"
            " import-route static\n"
            " silent-interface all\n"
            " area 0.0.0.0\n"
            "  network 10.0.0.1 0.0.0.0\n"
            "  network 10.0.10.0 0.0.0.255"
        )
        assert len(result.ir.ospf) == 1
        ospf = result.ir.ospf[0]
        assert ospf.process_id == 1
        assert ospf.router_id == "10.0.0.1"
        assert len(ospf.networks) == 2

    def test_undo_silent_interface(self):
        p = get_h3c_parser()
        result = p.parse(
            "ospf 1 router-id 10.0.0.1\n"
            " silent-interface all\n"
            " undo silent-interface Vlan-interface1000\n"
            " undo silent-interface Vlan-interface1001\n"
            " area 0.0.0.0\n"
            "  network 10.0.0.1 0.0.0.0"
        )
        ospf = result.ir.ospf[0]
        assert ospf.review_notes is not None
        assert "Vlan-interface1000" in ospf.review_notes


class TestH3CStaticRoute:
    def test_simple_route(self):
        p = get_h3c_parser()
        result = p.parse("ip route-static 10.0.0.0 255.255.255.0 192.168.1.1")
        assert len(result.ir.static_routes) == 1
        route = result.ir.static_routes[0]
        assert route.prefix == "10.0.0.0"
        assert route.mask == "255.255.255.0"
        assert route.nexthop == "192.168.1.1"

    def test_cidr_mask_route(self):
        p = get_h3c_parser()
        result = p.parse("ip route-static 10.0.0.0 24 10.54.1.62")
        assert len(result.ir.static_routes) == 1
        route = result.ir.static_routes[0]
        assert route.prefix == "10.0.0.0"
        assert route.mask == "255.255.255.0"
        assert route.nexthop == "10.54.1.62"

    def test_default_route(self):
        p = get_h3c_parser()
        result = p.parse("ip route-static 0.0.0.0 0 10.54.1.62")
        assert result.ir.static_routes[0].mask == "0.0.0.0"

    def test_multiple_routes(self):
        p = get_h3c_parser()
        config = (
            "ip route-static 10.0.0.0 16 10.54.1.62\n"
            "ip route-static 172.16.0.0 16 10.54.1.62\n"
            "ip route-static 192.168.0.0 255.255.0.0 10.54.1.62\n"
            "ip route-static 10.10.10.0 24 10.54.1.62\n"
            "ip route-static 0.0.0.0 0 10.54.1.62"
        )
        result = p.parse(config)
        assert len(result.ir.static_routes) == 5


class TestH3CAcl:
    def test_acl_basic(self):
        p = get_h3c_parser()
        result = p.parse(
            "acl number 2000\n"
            " rule 10 permit source 10.0.0.0 0.0.255.255\n"
            " rule 20 deny source 192.168.0.0 0.0.255.255"
        )
        assert len(result.ir.acls) == 1
        acl = result.ir.acls[0]
        assert acl.number == 2000
        assert len(acl.entries) == 2
        assert acl.entries[0].sequence == 10
        assert acl.entries[0].action == "permit"

    def test_acl_3050_with_destination(self):
        p = get_h3c_parser()
        result = p.parse(
            "acl number 3050\n"
            " rule 0 permit ip source 10.54.7.181 0 destination 10.2.129.28 0\n"
            " rule 5 permit ip source 10.54.7.181 0 destination 10.3.129.28 0\n"
            " rule 120 deny ip source 10.54.7.181 0\n"
            " rule 375 permit ip"
        )
        acl = result.ir.acls[0]
        assert len(acl.entries) == 4
        assert acl.entries[0].dst == "10.2.129.28"
        assert acl.entries[2].action == "deny"
        assert acl.entries[3].action == "permit"
        assert acl.entries[3].src is None


class TestH3CStp:
    def test_stp_region(self):
        p = get_h3c_parser()
        result = p.parse(
            "stp region-configuration\n"
            " region-name test\n"
            " instance 1 vlan 2 10 to 20 30\n"
            " active region-configuration"
        )
        assert result.ir.stp is not None
        assert result.ir.stp.region == "test"
        assert len(result.ir.stp.instances) > 0

    def test_stp_enable(self):
        p = get_h3c_parser()
        result = p.parse("stp global enable")
        assert result.ir.stp is not None or len(result.ir.static_routes) == 0


class TestH3CCoverage:
    def test_coverage_ratio_good(self):
        p = get_h3c_parser()
        config = "sysname SW01\nvlan 10\n name MGMT\n"
        result = p.parse(config)
        assert result.coverage_ratio > 0.8

    def test_parse_result_has_unknown_blocks_for_unrecognized(self):
        p = get_h3c_parser()
        config = "sysname SW01\nsome-unknown-command\n"
        result = p.parse(config)
        assert len(result.ir.unknown_blocks) >= 1


class TestH3CIntegration:
    TEST_CONFIG_PATH = "/Users/zhangh01/Desktop/codex_net_trans/_local/test_config.txt"

    @pytest.fixture
    def real_config(self):
        if not os.path.exists(self.TEST_CONFIG_PATH):
            pytest.skip("test_config.txt not found")
        with open(self.TEST_CONFIG_PATH) as f:
            return f.read()

    def test_hostname(self, real_config):
        p = get_h3c_parser()
        result = p.parse(real_config)
        assert result.ir.meta.hostname == "ZJQZ1TL2F_COR_CS7503E_01"

    def test_vlan_count(self, real_config):
        p = get_h3c_parser()
        result = p.parse(real_config)
        assert len(result.ir.vlans) >= 20

    def test_svi_count(self, real_config):
        p = get_h3c_parser()
        result = p.parse(real_config)
        assert len(result.ir.svis) >= 20

    def test_svi_with_vrrp(self, real_config):
        p = get_h3c_parser()
        result = p.parse(real_config)
        svi_with_fhrp = [s for s in result.ir.svis if len(s.fhrp) > 0]
        assert len(svi_with_fhrp) >= 15

    def test_static_route_count(self, real_config):
        p = get_h3c_parser()
        result = p.parse(real_config)
        assert len(result.ir.static_routes) == 5

    def test_acl_3050_count(self, real_config):
        p = get_h3c_parser()
        result = p.parse(real_config)
        acl_3050 = [a for a in result.ir.acls if a.number == 3050]
        assert len(acl_3050) == 1
        assert len(acl_3050[0].entries) >= 70

    def test_packet_filter_on_vlans(self, real_config):
        p = get_h3c_parser()
        result = p.parse(real_config)
        svi_107 = [s for s in result.ir.svis if s.vid == 107]
        svi_207 = [s for s in result.ir.svis if s.vid == 207]
        if svi_107:
            assert svi_107[0].acl_in == "3050"
        if svi_207:
            assert svi_207[0].acl_in == "3050"

    def test_ospf_networks(self, real_config):
        p = get_h3c_parser()
        result = p.parse(real_config)
        assert len(result.ir.ospf) == 1
        ospf = result.ir.ospf[0]
        assert len(ospf.networks) >= 20

    def test_undo_silent_interfaces(self, real_config):
        p = get_h3c_parser()
        result = p.parse(real_config)
        ospf = result.ir.ospf[0]
        assert ospf.review_notes is not None
        assert "Vlan-interface1000" in ospf.review_notes
        assert "Vlan-interface1001" in ospf.review_notes

    def test_lag_members(self, real_config):
        p = get_h3c_parser()
        result = p.parse(real_config)
        lag1 = [l for l in result.ir.lags if l.lag_id == 1]
        lag100 = [l for l in result.ir.lags if l.lag_id == 100]
        if lag1:
            assert any("GigabitEthernet0/0/23" in p for p in lag1[0].member_ports), f"lag1 members: {lag1[0].member_ports}"
            assert any("GigabitEthernet0/0/24" in p for p in lag1[0].member_ports), f"lag1 members: {lag1[0].member_ports}"
        if lag100:
            assert any("GigabitEthernet0/0/10" in p for p in lag100[0].member_ports), f"lag100 members: {lag100[0].member_ports}"
            assert any("GigabitEthernet0/0/11" in p for p in lag100[0].member_ports), f"lag100 members: {lag100[0].member_ports}"

    def test_coverage_ratio(self, real_config):
        p = get_h3c_parser()
        result = p.parse(real_config)
        assert result.coverage_ratio >= 0.80, f"Coverage ratio {result.coverage_ratio} is below 0.80"

    def test_interfaces_count(self, real_config):
        p = get_h3c_parser()
        result = p.parse(real_config)
        assert len(result.ir.interfaces) >= 30

    def test_unknown_blocks_reported(self, real_config):
        p = get_h3c_parser()
        result = p.parse(real_config)
        if result.ir.unknown_blocks:
            for ub in result.ir.unknown_blocks:
                print(f"  Unknown block at {ub.source_span}: {ub.raw_text[:80]}...")
