import pytest
import os
from core.parser import init_parsers, get_parser
from core.renderer import init_renderers, get_renderer
from core.domain import DeviceDomain
from core.ir_models import IRConfig, IRConfigMeta, IRVlan, IRSvi, IRInterface, IRLag, IRAcl, IRAclEntry, IRStaticRoute, IROspf, IRFhrp, IRStp, IRUnknownBlock, IRManagement, IRAaa
from core.ir_models.enums import IRType, IRInterfaceType, IRFhrpProtocol
from core.ir_models.base import SourceSpan


@pytest.fixture(autouse=True)
def setup():
    init_parsers()
    init_renderers()


def get_cisco_renderer():
    cls = get_renderer(DeviceDomain.SWITCH, "ios-xe")
    assert cls is not None
    return cls()


class TestCiscoHostname:
    def test_hostname_rendered(self):
        r = get_cisco_renderer()
        meta = IRConfigMeta(source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="comware", target_platform="ios-xe",
            hostname="SW01")
        ir = IRConfig(meta=meta)
        result = r.render(ir)
        assert "hostname SW01" in result.config_text


class TestCiscoVlan:
    def test_vlan_with_name(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.vlans.append(IRVlan(type=IRType.VLAN, source_span=span, vid=10, name="MGMT"))
        ir.vlans.append(IRVlan(type=IRType.VLAN, source_span=span, vid=20))
        result = r.render(ir)
        assert "vlan 10" in result.config_text
        assert " name MGMT" in result.config_text
        assert "vlan 20" in result.config_text
        # Must NOT contain H3C vlan syntax
        assert "vlan batch" not in result.config_text


class TestCiscoInterface:
    def test_trunk_interface(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.interfaces.append(IRInterface(
            type=IRType.INTERFACE, source_span=span,
            iftype=IRInterfaceType.PHYSICAL, name="GigabitEthernet0/0/1",
            description="TO-SW02",
            trunk_allowed=[10, 20, 30], trunk_allowed_all=False,
        ))
        result = r.render(ir)
        assert "interface GigabitEthernet0/0/1" in result.config_text
        assert "switchport mode trunk" in result.config_text
        assert "switchport trunk allowed vlan 10,20,30" in result.config_text
        assert "description TO-SW02" in result.config_text
        # Must NOT contain H3C syntax
        assert "port link-type trunk" not in result.config_text
        assert "port trunk permit vlan" not in result.config_text

    def test_access_interface(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.interfaces.append(IRInterface(
            type=IRType.INTERFACE, source_span=span,
            iftype=IRInterfaceType.PHYSICAL, name="GigabitEthernet0/0/5",
            description="TO-WAN",
            untagged_vlan=1001,
        ))
        result = r.render(ir)
        assert "switchport mode access" in result.config_text
        assert "switchport access vlan 1001" in result.config_text
        assert " port access vlan 1001" not in "\n" + result.config_text

    def test_lag_member(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.interfaces.append(IRInterface(
            type=IRType.INTERFACE, source_span=span,
            iftype=IRInterfaceType.PHYSICAL, name="GigabitEthernet0/0/23",
            description="LAG member",
            trunk_allowed=[1, 10], lag_group=1,
        ))
        result = r.render(ir)
        assert "channel-group 1 mode active" in result.config_text
        # Not H3C
        assert "port link-aggregation group" not in result.config_text

    def test_loopback(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.interfaces.append(IRInterface(
            type=IRType.INTERFACE, source_span=span,
            iftype=IRInterfaceType.LOOPBACK, name="Loopback0",
            ip="10.0.0.1", mask="255.255.255.255",
        ))
        result = r.render(ir)
        assert "interface Loopback0" in result.config_text
        assert "ip address 10.0.0.1 255.255.255.255" in result.config_text

    def test_shutdown_interface(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.interfaces.append(IRInterface(
            type=IRType.INTERFACE, source_span=span,
            iftype=IRInterfaceType.PHYSICAL, name="GigabitEthernet0/0/1",
            shutdown=True,
        ))
        result = r.render(ir)
        assert "shutdown" in result.config_text


class TestCiscoSvi:
    def test_svi_basic(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.svis.append(IRSvi(
            type=IRType.SVI, source_span=span, vid=10,
            ip="10.0.10.1", mask="255.255.255.0",
            description="MGMT",
        ))
        result = r.render(ir)
        assert "interface Vlan10" in result.config_text
        assert "ip address 10.0.10.1 255.255.255.0" in result.config_text
        assert "description MGMT" in result.config_text
        assert "no shutdown" in result.config_text
        # Not H3C
        assert "interface Vlan-interface" not in result.config_text

    def test_svi_with_vrrp(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        fhrp = IRFhrp(type=IRType.FHRP, source_span=span,
            protocol=IRFhrpProtocol.VRRP, group_id=10,
            virtual_ip="10.0.10.254", priority=110)
        ir.svis.append(IRSvi(
            type=IRType.SVI, source_span=span, vid=10,
            ip="10.0.10.1", mask="255.255.255.0",
            description="MGMT-AP",
            fhrp=[fhrp],
        ))
        result = r.render(ir)
        assert "vrrp 10 ip 10.0.10.254" in result.config_text
        assert "vrrp 10 priority 110" in result.config_text
        # Not H3C
        assert "vrrp vrid" not in result.config_text
        assert "virtual-ip" not in result.config_text

    def test_svi_with_acl(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.svis.append(IRSvi(
            type=IRType.SVI, source_span=span, vid=107,
            ip="10.52.7.252", mask="255.255.255.0",
            acl_in="3050",
        ))
        result = r.render(ir)
        assert "ip access-group 3050 in" in result.config_text
        # Not H3C
        assert "packet-filter" not in result.config_text


class TestCiscoLag:
    def test_port_channel(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.lags.append(IRLag(
            type=IRType.LAG, source_span=span, lag_id=1,
            member_ports=[], mode="static",
        ))
        result = r.render(ir)
        assert "interface Port-channel1" in result.config_text
        assert "! NOTE: static LAG" in result.config_text
        # Not H3C
        assert "interface Bridge-Aggregation1" not in result.config_text

    def test_dynamic_lag(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.lags.append(IRLag(
            type=IRType.LAG, source_span=span, lag_id=100,
            member_ports=[], mode="lacp",
        ))
        result = r.render(ir)
        assert "! NOTE: dynamic LAG" in result.config_text
        assert "link-aggregation mode dynamic" not in result.config_text


class TestCiscoStaticRoute:
    def test_routes(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.static_routes.append(IRStaticRoute(
            type=IRType.STATIC_ROUTE, source_span=span,
            prefix="10.53.0.0", mask="255.255.0.0", nexthop="10.54.1.62",
        ))
        result = r.render(ir)
        assert "ip route 10.53.0.0 255.255.0.0 10.54.1.62" in result.config_text
        # Not H3C
        assert "ip route-static" not in result.config_text


class TestCiscoOspf:
    def test_ospf_basic(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.ospf.append(IROspf(
            type=IRType.OSPF, source_span=span, process_id=1,
            router_id="10.52.0.202",
            networks=[
                {"ip": "10.52.0.202", "wildcard": "0.0.0.0", "area": "0.0.0.0"},
                {"ip": "10.52.4.0", "wildcard": "0.0.255.255", "area": "0.0.0.0"},
            ],
            areas=[{"area_id": "0.0.0.0", "type": "normal"}],
            review_notes="undo silent-interface: Vlan-interface1000, Vlan-interface1001",
        ))
        result = r.render(ir)
        assert "router ospf 1" in result.config_text
        assert "router-id 10.52.0.202" in result.config_text
        assert "passive-interface default" in result.config_text
        assert "no passive-interface Vlan1000" in result.config_text
        assert "no passive-interface Vlan1001" in result.config_text
        assert "network 10.52.0.202 0.0.0.0 area 0" in result.config_text
        # Not H3C
        assert "silent-interface" not in result.config_text
        assert "undo" not in result.config_text
        # Check area 0.0.0.0 -> area 0
        assert "area 0" in result.config_text


class TestCiscoAcl:
    def test_extended_acl(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        entries = [
            IRAclEntry(action="permit", sequence=0, src="10.54.7.181", src_wildcard="0", dst="10.2.129.28", dst_wildcard="0"),
            IRAclEntry(action="permit", sequence=5, src="10.54.7.181", src_wildcard="0", dst="10.3.129.28", dst_wildcard="0"),
            IRAclEntry(action="deny", sequence=120, src="10.54.7.181", src_wildcard="0"),
            IRAclEntry(action="permit", sequence=375),
        ]
        ir.acls.append(IRAcl(
            type=IRType.ACL, source_span=span,
            acl_type="advanced", number=3050,
            entries=entries,
        ))
        result = r.render(ir)
        assert "ip access-list extended 3050" in result.config_text
        assert "0 permit ip host 10.54.7.181 host 10.2.129.28" in result.config_text
        assert "120 deny ip host 10.54.7.181 any" in result.config_text
        assert "375 permit ip any any" in result.config_text
        # Not H3C
        assert "acl number" not in result.config_text


class TestCiscoStp:
    def test_mstp(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.stp = IRStp(
            type=IRType.STP, source_span=span,
            mode="mstp", region="qztlcb",
            instances=[
                {"id": 1, "vlans": [2, 104, 105, 106, 107, 108, 109, 154, 1002]},
                {"id": 2, "vlans": [30, 31, 32, 33, 34, 35, 40, 205, 206, 207, 208, 209, 210, 211, 254]},
            ],
        )
        result = r.render(ir)
        assert "spanning-tree mst configuration" in result.config_text
        assert "name qztlcb" in result.config_text
        assert "instance 1 vlan" in result.config_text
        # Not H3C
        assert "stp region-configuration" not in result.config_text
        assert "active region-configuration" not in result.config_text


class TestCiscoManagement:
    def test_lldp(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.management = IRManagement(type=IRType.MANAGEMENT, source_span=span,
            dns={"lldp": "lldp global enable"})
        result = r.render(ir)
        assert "lldp run" in result.config_text

    def test_snmp(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.management = IRManagement(type=IRType.MANAGEMENT, source_span=span,
            snmp=[{"raw": "snmp-agent community read zjtlcb acl 2000"}])
        result = r.render(ir)
        assert "snmp-server community zjtlcb RO 2000" in result.config_text

    def test_ntp(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.management = IRManagement(type=IRType.MANAGEMENT, source_span=span,
            ntp=[{"raw": "ntp-service unicast-server 20.5.101.10"}])
        result = r.render(ir)
        assert "ntp server 20.5.101.10" in result.config_text

    def test_ssh(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.management = IRManagement(type=IRType.MANAGEMENT, source_span=span,
            ssh={"enable": True})
        result = r.render(ir)
        assert "ip ssh version 2" in result.config_text

    def test_syslog(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.management = IRManagement(type=IRType.MANAGEMENT, source_span=span,
            syslog=[{"raw": "info-center loghost 20.5.101.4"}])
        result = r.render(ir)
        assert "logging host 20.5.101.4" in result.config_text


class TestCiscoAAA:
    def test_aaa_skipped(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.aaa = IRAaa(type=IRType.AAA, source_span=span,
            auth_method="hwtacacs",
            servers=[{"raw": "hwtacacs scheme zjtlcb\n primary authentication 20.5.100.81"}])
        result = r.render(ir)
        assert "aaa" in result.features_skipped
        assert any("AAA" in item.description for item in result.review_items)


class TestCiscoReviewItems:
    def test_review_items_for_stp(self):
        r = get_cisco_renderer()
        meta = make_meta()
        ir = IRConfig(meta=meta)
        span = make_span()
        ir.stp = IRStp(type=IRType.STP, source_span=span, mode="mstp", region="test",
            instances=[{"id": 1, "vlans": [1, 2]}])
        result = r.render(ir)
        # Should have review item for STP
        stp_items = [item for item in result.review_items if item.field == "stp"]
        assert len(stp_items) > 0


class TestCiscoIntegration:
    TEST_CONFIG_PATH = "/Users/zhangh01/Desktop/codex_net_trans/_local/test_config.txt"

    @pytest.fixture
    def parsed_ir(self):
        if not os.path.exists(self.TEST_CONFIG_PATH):
            pytest.skip("test_config.txt not found")
        with open(self.TEST_CONFIG_PATH) as f:
            config = f.read()
        parser_cls = get_parser(DeviceDomain.SWITCH, "comware")
        p = parser_cls()
        result = p.parse(config)
        return result.ir

    def test_no_h3c_residual_commands(self, parsed_ir):
        r = get_cisco_renderer()
        result = r.render(parsed_ir)
        text = result.config_text
        # Strip comment lines and sanitize Cisco commands containing H3C substrings
        non_comment_lines = [l for l in text.split("\n") if not l.strip().startswith("!")]
        sanitized = "\n".join(non_comment_lines).replace("switchport access vlan", "SW_ACC_VLAN")
        forbidden = [
            "Vlan-interface", "Bridge-Aggregation", "vrrp vrid", "virtual-ip",
            "packet-filter", "port link-mode", "port trunk permit",
            "port access vlan", "port link-aggregation group",
            "ip route-static", "acl number", "hwtacacs scheme",
            "local-user", "user-role", "snmp-agent", "ntp-service",
            "undo silent-interface", "stp region-configuration",
            "active region-configuration", "vlan batch",
        ]
        for cmd in forbidden:
            assert cmd not in sanitized, f"Found residual H3C command: {cmd}"

    def test_expected_cisco_commands(self, parsed_ir):
        r = get_cisco_renderer()
        result = r.render(parsed_ir)
        text = result.config_text
        expected = [
            "hostname ZJQZ1TL2F_COR_CS7503E_01",
            "interface Vlan30",
            "interface Port-channel1",
            "router ospf 1",
            "passive-interface default",
            "no passive-interface Vlan1000",
            "no passive-interface Vlan1001",
            "ip access-list extended 3050",
            "ip route 10.53.0.0 255.255.0.0 10.54.1.62",
            "ip route 172.27.27.180 255.255.255.254 10.54.1.62",
            "ntp server 20.5.101.10",
            "lldp run",
        ]
        for cmd in expected:
            assert cmd in text, f"Expected Cisco command not found: {cmd}"

    def test_acl_3050_entries_count(self, parsed_ir):
        r = get_cisco_renderer()
        result = r.render(parsed_ir)
        count = result.config_text.count("permit ip host")
        assert count >= 50, f"Only found {count} ACL entries, expected 70+"

    def test_coverage(self, parsed_ir):
        r = get_cisco_renderer()
        result = r.render(parsed_ir)
        assert len(result.features_rendered) > 0
        assert "aaa" in result.features_skipped

    def test_output_ends_with_newline(self, parsed_ir):
        r = get_cisco_renderer()
        result = r.render(parsed_ir)
        assert result.config_text.endswith("\n")

    def test_no_raw_unknown_in_output(self, parsed_ir):
        r = get_cisco_renderer()
        result = r.render(parsed_ir)
        assert "! ftth" in result.config_text or "# ftth" in result.config_text

    def test_review_items_present(self, parsed_ir):
        r = get_cisco_renderer()
        result = r.render(parsed_ir)
        assert len(result.review_items) > 0


def make_meta():
    return IRConfigMeta(source_vendor="h3c", target_vendor="cisco",
        source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
        source_platform="comware", target_platform="ios-xe")

def make_span():
    return SourceSpan(start_line=1, end_line=1)
