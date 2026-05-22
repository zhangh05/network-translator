from __future__ import annotations

import pytest

from core.ir_models import (
    ConversionStatus,
    IRAaa,
    IRAcl,
    IRAclEntry,
    IRAddressObject,
    IRBgp,
    IRConfig,
    IRConfigMeta,
    IRFhrp,
    IRFhrpProtocol,
    IRInterface,
    IRInterfaceType,
    IRIpsecVpn,
    IRLag,
    IRManagement,
    IRNat,
    IRNatRule,
    IROspf,
    IRPbr,
    IRServiceObject,
    IRSecurityPolicy,
    IRStaticRoute,
    IRStp,
    IRSvi,
    IRType,
    IRUnsupported,
    IRUnknownBlock,
    IRVlan,
    IRVrf,
    IRZone,
    SourceSpan,
)
from core.domain import DeviceDomain


class TestIRInterface:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=1)
        iface = IRInterface(type=IRType.INTERFACE, source_span=span, iftype=IRInterfaceType.PHYSICAL, name="GigabitEthernet0/1")
        assert iface.name == "GigabitEthernet0/1"
        assert iface.iftype == IRInterfaceType.PHYSICAL
        assert iface.shutdown is False

    def test_with_trunk(self):
        span = SourceSpan(start_line=1, end_line=3)
        iface = IRInterface(type=IRType.INTERFACE, source_span=span, iftype=IRInterfaceType.PHYSICAL, name="GigabitEthernet0/1", trunk_allowed=[10, 20], trunk_allowed_all=False)
        assert iface.trunk_allowed == [10, 20]


class TestIRStaticRoute:
    def test_basic(self):
        span = SourceSpan(start_line=5, end_line=5)
        route = IRStaticRoute(type=IRType.STATIC_ROUTE, source_span=span, prefix="10.0.0.0", mask="255.255.255.0", nexthop="192.168.1.1")
        assert route.prefix == "10.0.0.0"
        assert route.nexthop == "192.168.1.1"

    def test_with_metric_vrf(self):
        span = SourceSpan(start_line=6, end_line=6)
        route = IRStaticRoute(type=IRType.STATIC_ROUTE, source_span=span, prefix="0.0.0.0", mask="0.0.0.0", nexthop="10.0.0.1", metric=1, vrf="MGMT")
        assert route.metric == 1
        assert route.vrf == "MGMT"

    def test_with_distance_tag_description(self):
        span = SourceSpan(start_line=7, end_line=7)
        route = IRStaticRoute(type=IRType.STATIC_ROUTE, source_span=span, prefix="10.0.0.0", mask="255.255.255.0", nexthop="192.168.1.1", distance=10, tag=100, description="backup path")
        assert route.distance == 10
        assert route.tag == 100
        assert route.description == "backup path"


class TestIRAcl:
    def test_entry(self):
        entry = IRAclEntry(action="permit", protocol="tcp", src="10.0.0.0", src_wildcard="0.0.0.255", dst="any", dst_port="80")
        assert entry.action == "permit"
        assert entry.protocol == "tcp"

    def test_entry_full(self):
        entry = IRAclEntry(sequence=10, action="deny", protocol="icmp", src="any", dst="any", remark="block icmp", established=False, logging=True)
        assert entry.sequence == 10
        assert entry.remark == "block icmp"
        assert entry.logging is True

    def test_acl(self):
        span = SourceSpan(start_line=10, end_line=20)
        entry = IRAclEntry(action="deny", protocol="icmp", src="any", dst="any")
        acl = IRAcl(type=IRType.ACL, source_span=span, acl_type="extended", number=100, entries=[entry])
        assert acl.number == 100
        assert len(acl.entries) == 1

    def test_named_acl(self):
        span = SourceSpan(start_line=1, end_line=2)
        acl = IRAcl(type=IRType.ACL, source_span=span, acl_type="standard", name="BLOCK_RFC1918")
        assert acl.name == "BLOCK_RFC1918"


class TestIRAaa:
    def test_basic(self):
        span = SourceSpan(start_line=1, end_line=1)
        aaa = IRAaa(type=IRType.AAA, source_span=span, auth_method="local")
        assert aaa.auth_method == "local"

    def test_with_accounting_servers(self):
        span = SourceSpan(start_line=1, end_line=3)
        aaa = IRAaa(type=IRType.AAA, source_span=span, auth_method="radius", accounting="start-stop", servers=[{"ip": "10.0.0.5", "type": "radius"}])
        assert aaa.accounting == "start-stop"
        assert len(aaa.servers) == 1


class TestIRManagement:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=1)
        mgmt = IRManagement(type=IRType.MANAGEMENT, source_span=span)
        assert mgmt.snmp == []

    def test_with_ntp(self):
        span = SourceSpan(start_line=1, end_line=1)
        mgmt = IRManagement(type=IRType.MANAGEMENT, source_span=span, ntp=[{"server": "pool.ntp.org"}])
        assert len(mgmt.ntp) == 1

    def test_with_all(self):
        span = SourceSpan(start_line=1, end_line=10)
        mgmt = IRManagement(
            type=IRType.MANAGEMENT, source_span=span,
            snmp=[{"community": "public", "access": "ro"}],
            ntp=[{"server": "pool.ntp.org"}],
            syslog=[{"server": "10.0.0.99"}],
            ssh={"version": 2, "timeout": 120},
            dns={"servers": ["8.8.8.8"]},
        )
        assert len(mgmt.snmp) == 1
        assert len(mgmt.syslog) == 1
        assert mgmt.ssh["version"] == 2
        assert "8.8.8.8" in mgmt.dns["servers"]


class TestIRVlan:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=1)
        vlan = IRVlan(type=IRType.VLAN, source_span=span, vid=10)
        assert vlan.vid == 10
        assert vlan.name is None

    def test_with_name(self):
        span = SourceSpan(start_line=1, end_line=1)
        vlan = IRVlan(type=IRType.VLAN, source_span=span, vid=10, name="MGMT")
        assert vlan.vid == 10
        assert vlan.name == "MGMT"


class TestIRFhrp:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=3)
        fhrp = IRFhrp(type=IRType.FHRP, source_span=span, protocol=IRFhrpProtocol.VRRP, group_id=1, virtual_ip="10.0.0.1")
        assert fhrp.protocol == IRFhrpProtocol.VRRP
        assert fhrp.group_id == 1
        assert fhrp.priority == 100

    def test_with_preempt(self):
        span = SourceSpan(start_line=1, end_line=3)
        fhrp = IRFhrp(type=IRType.FHRP, source_span=span, protocol=IRFhrpProtocol.VRRP, group_id=1, virtual_ip="10.0.0.1", priority=120, preempt=True)
        assert fhrp.preempt is True

    def test_with_track_auth(self):
        span = SourceSpan(start_line=1, end_line=5)
        fhrp = IRFhrp(type=IRType.FHRP, source_span=span, protocol=IRFhrpProtocol.HSRP, group_id=10, virtual_ip="10.0.0.254", track=[{"interface": "G0/1", "decrement": 10}], authentication="cisco123")
        assert fhrp.authentication == "cisco123"
        assert len(fhrp.track) == 1


class TestIRSvi:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=5)
        svi = IRSvi(type=IRType.SVI, source_span=span, vid=100, ip="10.0.100.1", mask="255.255.255.0")
        assert svi.vid == 100
        assert svi.ip == "10.0.100.1"

    def test_with_fhrp(self):
        span = SourceSpan(start_line=1, end_line=5)
        fhrp_span = SourceSpan(start_line=1, end_line=5)
        fhrp = IRFhrp(type=IRType.FHRP, source_span=fhrp_span, protocol=IRFhrpProtocol.VRRP, group_id=1, virtual_ip="10.0.100.254")
        svi = IRSvi(type=IRType.SVI, source_span=span, vid=100, ip="10.0.100.1", mask="255.255.255.0", fhrp=[fhrp])
        assert len(svi.fhrp) == 1
        assert svi.fhrp[0].protocol == IRFhrpProtocol.VRRP

    def test_with_acl_shutdown(self):
        span = SourceSpan(start_line=1, end_line=5)
        svi = IRSvi(type=IRType.SVI, source_span=span, vid=200, shutdown=True, acl_in="INBOUND", acl_out="OUTBOUND", description="DMZ Interface")
        assert svi.shutdown is True
        assert svi.acl_in == "INBOUND"
        assert svi.description == "DMZ Interface"


class TestIRLag:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=3)
        lag = IRLag(type=IRType.LAG, source_span=span, lag_id=1)
        assert lag.lag_id == 1
        assert lag.mode == "static"

    def test_with_members(self):
        span = SourceSpan(start_line=1, end_line=3)
        lag = IRLag(type=IRType.LAG, source_span=span, lag_id=1, member_ports=["GigabitEthernet0/1", "GigabitEthernet0/2"], mode="lacp")
        assert lag.lag_id == 1
        assert len(lag.member_ports) == 2
        assert lag.mode == "lacp"

    def test_lacp_mode_default(self):
        span = SourceSpan(start_line=1, end_line=3)
        lag = IRLag(type=IRType.LAG, source_span=span, lag_id=2, member_ports=["GigabitEthernet0/3"], mode="lacp")
        assert lag.lacp_mode == "active"


class TestIRStp:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=5)
        stp = IRStp(type=IRType.STP, source_span=span)
        assert stp.mode is None

    def test_with_fields(self):
        span = SourceSpan(start_line=1, end_line=5)
        stp = IRStp(type=IRType.STP, source_span=span, mode="mstp", region="REGION1", revision=1)
        assert stp.mode == "mstp"
        assert stp.revision == 1

    def test_with_instances_priority(self):
        span = SourceSpan(start_line=1, end_line=10)
        stp = IRStp(type=IRType.STP, source_span=span, mode="pvst", instances=[{"vlan": 10, "root_priority": 4096}], priority={"default": 32768})
        assert len(stp.instances) == 1
        assert stp.priority["default"] == 32768


class TestIROspf:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=5)
        ospf = IROspf(type=IRType.OSPF, source_span=span, process_id=1, router_id="1.1.1.1")
        assert ospf.process_id == 1
        assert ospf.router_id == "1.1.1.1"

    def test_with_networks_areas(self):
        span = SourceSpan(start_line=1, end_line=10)
        ospf = IROspf(type=IRType.OSPF, source_span=span, process_id=10, router_id="10.0.0.1",
                       networks=[{"prefix": "10.0.0.0", "mask": "255.255.255.0", "area": "0.0.0.0"}],
                       areas=[{"id": "0.0.0.0", "type": "normal"}])
        assert len(ospf.networks) == 1
        assert len(ospf.areas) == 1

    def test_passive_interfaces_ref_bw(self):
        span = SourceSpan(start_line=1, end_line=10)
        ospf = IROspf(type=IRType.OSPF, source_span=span, process_id=1, router_id="2.2.2.2",
                       passive_interfaces=["GigabitEthernet0/1", "GigabitEthernet0/2"],
                       reference_bandwidth=1000)
        assert len(ospf.passive_interfaces) == 2
        assert ospf.reference_bandwidth == 1000

    def test_redistribute(self):
        span = SourceSpan(start_line=1, end_line=8)
        ospf = IROspf(type=IRType.OSPF, source_span=span, process_id=1, router_id="3.3.3.3",
                       redistributes=[{"protocol": "bgp", "route_map": "FROM_BGP"}])
        assert len(ospf.redistributes) == 1


class TestIRBgp:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=5)
        bgp = IRBgp(type=IRType.BGP, source_span=span, asn=65001, router_id="2.2.2.2")
        assert bgp.asn == 65001

    def test_with_peers_networks(self):
        span = SourceSpan(start_line=1, end_line=10)
        bgp = IRBgp(type=IRType.BGP, source_span=span, asn=65001, router_id="2.2.2.2",
                     peers=[{"ip": "10.0.0.1", "remote_as": 65002}],
                     networks=["10.0.0.0/24", "192.168.1.0/24"])
        assert len(bgp.peers) == 1
        assert len(bgp.networks) == 2

    def test_redistribute(self):
        span = SourceSpan(start_line=1, end_line=8)
        bgp = IRBgp(type=IRType.BGP, source_span=span, asn=65001, router_id="2.2.2.2",
                     redistribute=["ospf", "connected"])
        assert "ospf" in bgp.redistribute


class TestIRVrf:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=3)
        vrf = IRVrf(type=IRType.VRF, source_span=span, name="MGMT", rd="1:100")
        assert vrf.name == "MGMT"
        assert vrf.rd == "1:100"

    def test_with_rt(self):
        span = SourceSpan(start_line=1, end_line=3)
        vrf = IRVrf(type=IRType.VRF, source_span=span, name="CUSTOMER_A", rd="65001:100", import_rt=["65001:100"], export_rt=["65001:100"])
        assert "65001:100" in vrf.import_rt
        assert "65001:100" in vrf.export_rt

    def test_no_rd_name_only(self):
        span = SourceSpan(start_line=1, end_line=1)
        vrf = IRVrf(type=IRType.VRF, source_span=span, name="default")
        assert vrf.name == "default"
        assert vrf.rd is None


class TestIRPbr:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=5)
        pbr = IRPbr(type=IRType.PBR, source_span=span, name="PBR-TRAFFIC", rules=[{"seq": 10, "match": "ip", "set": "nexthop 10.0.0.1"}])
        assert pbr.name == "PBR-TRAFFIC"

    def test_empty_rules(self):
        span = SourceSpan(start_line=1, end_line=1)
        pbr = IRPbr(type=IRType.PBR, source_span=span, name="PBR-EMPTY")
        assert pbr.rules == []


class TestIRNat:
    def test_basic(self):
        span = SourceSpan(start_line=1, end_line=3)
        nat = IRNat(type=IRType.NAT, source_span=span, rules=[{"inside": "10.0.0.0/8", "outside": "200.1.1.1"}])
        assert len(nat.rules) == 1

    def test_empty(self):
        span = SourceSpan(start_line=1, end_line=1)
        nat = IRNat(type=IRType.NAT, source_span=span)
        assert nat.rules == []


class TestIRIpsecVpn:
    def test_with_connections(self):
        span = SourceSpan(start_line=1, end_line=10)
        vpn = IRIpsecVpn(type=IRType.IPSEC_VPN, source_span=span, connections=[{"peer": "200.1.1.1", "ike_version": "v2"}])
        assert len(vpn.connections) == 1

    def test_empty(self):
        span = SourceSpan(start_line=1, end_line=1)
        vpn = IRIpsecVpn(type=IRType.IPSEC_VPN, source_span=span)
        assert vpn.connections == []


class TestIRZone:
    def test_basic(self):
        span = SourceSpan(start_line=1, end_line=1)
        zone = IRZone(type=IRType.ZONE, source_span=span, name="trust", members=["GigabitEthernet0/1"])
        assert zone.name == "trust"
        assert "GigabitEthernet0/1" in zone.members

    def test_empty_members(self):
        span = SourceSpan(start_line=1, end_line=1)
        zone = IRZone(type=IRType.ZONE, source_span=span, name="untrust")
        assert zone.members == []


class TestIRAddressObject:
    def test_ip(self):
        span = SourceSpan(start_line=1, end_line=1)
        addr = IRAddressObject(type=IRType.ADDRESS_OBJECT, source_span=span, name="WEB_SERVER", ip="10.0.1.100")
        assert addr.name == "WEB_SERVER"

    def test_network(self):
        span = SourceSpan(start_line=1, end_line=1)
        addr = IRAddressObject(type=IRType.ADDRESS_OBJECT, source_span=span, name="LAN_SUBNET", network="10.0.0.0/24")
        assert addr.network == "10.0.0.0/24"

    def test_range(self):
        span = SourceSpan(start_line=1, end_line=1)
        addr = IRAddressObject(type=IRType.ADDRESS_OBJECT, source_span=span, name="DHCP_POOL", range="10.0.0.10-10.0.0.100")
        assert addr.range == "10.0.0.10-10.0.0.100"

    def test_fqdn(self):
        span = SourceSpan(start_line=1, end_line=1)
        addr = IRAddressObject(type=IRType.ADDRESS_OBJECT, source_span=span, name="MY_SERVER", fqdn="server.example.com")
        assert addr.fqdn == "server.example.com"


class TestIRServiceObject:
    def test_basic(self):
        span = SourceSpan(start_line=1, end_line=1)
        svc = IRServiceObject(type=IRType.SERVICE_OBJECT, source_span=span, name="HTTP", protocol="tcp", port="80")
        assert svc.name == "HTTP"
        assert svc.port == "80"

    def test_port_range(self):
        span = SourceSpan(start_line=1, end_line=1)
        svc = IRServiceObject(type=IRType.SERVICE_OBJECT, source_span=span, name="HIGH_PORTS", protocol="tcp", port_range="1024-65535")
        assert svc.port_range == "1024-65535"


class TestIRSecurityPolicy:
    def test_basic(self):
        span = SourceSpan(start_line=1, end_line=5)
        policy = IRSecurityPolicy(type=IRType.SECURITY_POLICY, source_span=span, name="AllowWeb", from_zone="trust", to_zone="untrust", src_addresses=["LAN_SUBNET"], dst_addresses=["WEB_SERVER"], services=["HTTP"])
        assert policy.name == "AllowWeb"
        assert policy.action == "permit"

    def test_default_fields(self):
        span = SourceSpan(start_line=1, end_line=1)
        policy = IRSecurityPolicy(type=IRType.SECURITY_POLICY, source_span=span, name="DefaultDeny")
        assert policy.action == "permit"
        assert policy.logging is False
        assert policy.session_stateful is True

    def test_deny_log(self):
        span = SourceSpan(start_line=1, end_line=3)
        policy = IRSecurityPolicy(type=IRType.SECURITY_POLICY, source_span=span, from_zone="untrust", to_zone="trust", action="deny", logging=True, description="Block all from untrusted")
        assert policy.action == "deny"
        assert policy.logging is True
        assert policy.description == "Block all from untrusted"


class TestIRNatRule:
    def test_source_nat(self):
        span = SourceSpan(start_line=1, end_line=3)
        rule = IRNatRule(type=IRType.NAT_RULE, source_span=span, name="SNAT-LAN", original_ip="10.0.0.0/24", translated_ip="200.1.1.1", nat_type="source")
        assert rule.name == "SNAT-LAN"
        assert rule.nat_type == "source"

    def test_destination_nat(self):
        span = SourceSpan(start_line=1, end_line=3)
        rule = IRNatRule(type=IRType.NAT_RULE, source_span=span, name="DNAT-WEB", original_ip="200.1.1.10", translated_ip="10.0.0.10", nat_type="destination", service="tcp/80")
        assert rule.service == "tcp/80"

    def test_with_zones(self):
        span = SourceSpan(start_line=1, end_line=3)
        rule = IRNatRule(type=IRType.NAT_RULE, source_span=span, original_ip="10.0.0.0/24", nat_type="source", from_zone="trust", to_zone="untrust", interface="WAN")
        assert rule.from_zone == "trust"
        assert rule.interface == "WAN"


class TestIRUnsupported:
    def test_basic(self):
        span = SourceSpan(start_line=1, end_line=2)
        unsup = IRUnsupported(type=IRType.UNSUPPORTED, source_span=span, raw_text="some proprietary command", unsupported_reason="no equivalent in target")
        assert unsup.raw_text == "some proprietary command"
        assert unsup.unsupported_reason == "no equivalent in target"

    def test_defaults(self):
        span = SourceSpan(start_line=1, end_line=1)
        unsup = IRUnsupported(type=IRType.UNSUPPORTED, source_span=span)
        assert unsup.raw_text == ""
        assert unsup.unsupported_reason == ""


class TestIRUnknownBlock:
    def test_basic(self):
        span = SourceSpan(start_line=10, end_line=15)
        unk = IRUnknownBlock(type=IRType.UNKNOWN, source_span=span, raw_text="unparsed config block")
        assert unk.raw_text == "unparsed config block"

    def test_defaults(self):
        span = SourceSpan(start_line=1, end_line=1)
        unk = IRUnknownBlock(type=IRType.UNKNOWN, source_span=span)
        assert unk.raw_text == ""


class TestIRConfigAggregation:
    def test_with_vlans_interfaces(self):
        span = SourceSpan(start_line=1, end_line=1)
        meta = IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="comware", target_platform="ios_xe",
        )
        vlan = IRVlan(type=IRType.VLAN, source_span=span, vid=10)
        iface = IRInterface(type=IRType.INTERFACE, source_span=span, iftype=IRInterfaceType.PHYSICAL, name="GigabitEthernet0/1")
        config = IRConfig(meta=meta, vlans=[vlan], interfaces=[iface])
        assert len(config.vlans) == 1
        assert len(config.interfaces) == 1
        assert config.vlans[0].vid == 10
        assert config.interfaces[0].name == "GigabitEthernet0/1"

    def test_with_all_collections(self):
        span = SourceSpan(start_line=1, end_line=1)
        meta = IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="comware", target_platform="ios_xe",
        )
        config = IRConfig(
            meta=meta,
            interfaces=[IRInterface(type=IRType.INTERFACE, source_span=span, iftype=IRInterfaceType.PHYSICAL, name="G0/1")],
            static_routes=[IRStaticRoute(type=IRType.STATIC_ROUTE, source_span=span, prefix="0.0.0.0", mask="0.0.0.0", nexthop="10.0.0.1")],
            ospf=[IROspf(type=IRType.OSPF, source_span=span, process_id=1, router_id="1.1.1.1")],
            bgp=[IRBgp(type=IRType.BGP, source_span=span, asn=65001, router_id="2.2.2.2")],
            fhrps=[IRFhrp(type=IRType.FHRP, source_span=span, protocol=IRFhrpProtocol.VRRP, group_id=1, virtual_ip="10.0.0.1")],
        )
        assert len(config.interfaces) == 1
        assert len(config.static_routes) == 1
        assert len(config.ospf) == 1
        assert len(config.bgp) == 1
        assert len(config.fhrps) == 1
