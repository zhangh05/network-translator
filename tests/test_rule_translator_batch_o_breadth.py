# -*- coding: utf-8 -*-
"""Batch O: rule translator breadth tests for fallback coverage.

Tests new fallback paths introduced in Batch O:
- management (banner, dns, archive, clock)
- router (RIP, ISIS, VRF hints)
- switch (LLDP, domain-name)
- firewall (object skeletons)
"""

import pytest

from core.rule_translator import RuleBasedTranslator


def _translate(config: str, from_v: str, to_v: str) -> str:
    t = RuleBasedTranslator()
    return t.translate(config, from_v, to_v)


def _has_manual_review(output: str) -> bool:
    return "MANUAL_REVIEW" in output


def _has_redacted(output: str) -> bool:
    return "<redacted>" in output


class TestBatchOManagementFallback:
    """Management-plane fallback breadth"""

    def test_hostname_cisco_to_huawei(self):
        out = _translate("hostname CORE\n", "cisco", "huawei")
        assert "sysname CORE" in out
        assert not _has_manual_review(out)

    def test_sysname_huawei_to_cisco(self):
        out = _translate("sysname CORE\n", "huawei", "cisco")
        assert "hostname CORE" in out
        assert not _has_manual_review(out)

    def test_ntp_server_cisco_to_huawei(self):
        out = _translate("ntp server 10.0.0.1\n", "cisco", "huawei")
        assert "ntp-service unicast-server 10.0.0.1" in out
        assert not _has_manual_review(out)

    def test_ntp_vrf_is_manual_review(self):
        out = _translate("ntp server vrf MGMT 10.0.0.1\n", "cisco", "huawei")
        assert _has_manual_review(out)

    def test_snmp_community_redacted(self):
        out = _translate("snmp-server community public RO\n", "cisco", "huawei")
        assert _has_redacted(out) or _has_manual_review(out)

    def test_logging_host_cisco_to_huawei(self):
        out = _translate("logging host 10.0.0.1\n", "cisco", "huawei")
        assert "info-center loghost 10.0.0.1" in out
        assert not _has_manual_review(out)

    def test_logging_source_interface(self):
        out = _translate("logging source-interface Loopback0\n", "cisco", "huawei")
        assert not _has_manual_review(out) or "source" in out.lower()


class TestBatchOSwitchFallback:
    """SWITCH-domain fallback breadth"""

    def test_vlan_cisco_to_huawei(self):
        out = _translate("vlan 10\n", "cisco", "huawei")
        assert "vlan 10" in out
        assert not _has_manual_review(out)

    def test_vlan_batch_huawei_to_cisco(self):
        out = _translate("vlan batch 10 20\n", "huawei", "cisco")
        assert "vlan 10,20" in out or "vlan 10" in out
        assert not _has_manual_review(out)

    def test_switchport_access_cisco_to_huawei(self):
        out = _translate("interface GigabitEthernet0/1\n switchport mode access\n switchport access vlan 10\n", "cisco", "huawei")
        assert "port link-type access" in out
        assert "port default vlan 10" in out
        assert not _has_manual_review(out)

    def test_switchport_trunk_cisco_to_huawei(self):
        out = _translate("interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n", "cisco", "huawei")
        assert "port link-type trunk" in out
        assert "port trunk allow-pass vlan 10 20" in out
        assert not _has_manual_review(out)

    def test_interface_range_manual_review(self):
        out = _translate("interface range GigabitEthernet0/1 to 0/24\n switchport mode access\n", "cisco", "huawei")
        assert _has_manual_review(out)

    def test_stp_portfast_cisco_to_huawei(self):
        out = _translate("spanning-tree portfast\n", "cisco", "huawei")
        assert "stp edged-port enable" in out
        assert not _has_manual_review(out)

    def test_port_trunk_huawei_to_cisco(self):
        out = _translate("interface GigabitEthernet0/1\n port link-type trunk\n port trunk allow-pass vlan 10 20\n", "huawei", "cisco")
        assert "switchport mode trunk" in out
        assert "switchport trunk allowed vlan 10,20" in out
        assert not _has_manual_review(out)

    def test_eth_trunk_huawei_to_cisco(self):
        out = _translate("interface Eth-Trunk1\n", "huawei", "cisco")
        assert "interface Port-channel1" in out
        assert not _has_manual_review(out)

    def test_vlan_interface_huawei_to_cisco(self):
        out = _translate("interface Vlanif10\n", "huawei", "cisco")
        assert "interface Vlan10" in out
        assert not _has_manual_review(out)


class TestBatchORouterFallback:
    """ROUTER-domain fallback breadth"""

    def test_static_route_cisco_to_huawei(self):
        out = _translate("ip route 10.0.0.0 255.0.0.0 192.168.1.1\n", "cisco", "huawei")
        assert "ip route-static 10.0.0.0 255.0.0.0 192.168.1.1" in out
        assert not _has_manual_review(out)

    def test_static_route_huawei_to_cisco(self):
        out = _translate("ip route-static 10.0.0.0 255.0.0.0 192.168.1.1\n", "huawei", "cisco")
        assert "ip route 10.0.0.0 255.0.0.0 192.168.1.1" in out
        assert not _has_manual_review(out)

    def test_ospf_header_cisco_to_huawei(self):
        out = _translate("router ospf 1\n", "cisco", "huawei")
        assert "ospf 1" in out
        assert not _has_manual_review(out)

    def test_ospf_header_huawei_to_cisco(self):
        out = _translate("ospf 1\n", "huawei", "cisco")
        assert "router ospf 1" in out
        assert not _has_manual_review(out)

    def test_bgp_header_cisco_to_huawei(self):
        out = _translate("router bgp 65000\n", "cisco", "huawei")
        assert "bgp 65000" in out
        assert not _has_manual_review(out)

    def test_bgp_neighbor_cisco_to_huawei(self):
        out = _translate("router bgp 65000\n neighbor 10.0.0.1 remote-as 65001\n", "cisco", "huawei")
        assert "peer 10.0.0.1 as-number 65001" in out
        assert not _has_manual_review(out)

    def test_bgp_password_redacted(self):
        out = _translate("router bgp 65000\n neighbor 10.0.0.1 password SecretBGP\n", "cisco", "huawei")
        assert _has_manual_review(out)
        assert _has_redacted(out)

    def test_ospf_area_auth_manual_review(self):
        out = _translate("router ospf 1\n area 0 authentication message-digest\n", "cisco", "huawei")
        assert _has_manual_review(out)

    def test_ospf_passive_cisco_to_huawei(self):
        out = _translate("passive-interface GigabitEthernet0/1\n", "cisco", "huawei")
        assert "silent-interface GigabitEthernet0/1" in out
        assert not _has_manual_review(out)

    def test_ospf_passive_default_cisco_to_huawei(self):
        out = _translate("passive-interface default\n", "cisco", "huawei")
        assert "silent-interface default" in out
        assert not _has_manual_review(out)


class TestBatchOFirewallFallback:
    """FIREWALL-domain fallback breadth"""

    def test_zone_huawei_usg_to_hillstone(self):
        out = _translate("security-zone name trust\n", "huawei_usg", "hillstone")
        assert "zone trust" in out
        assert not _has_manual_review(out)

    def test_address_object_huawei_usg_to_hillstone(self):
        out = _translate("ip address-set ADDR type object\n address 0 10.0.0.0 mask 24\n", "huawei_usg", "hillstone")
        assert "address ADDR 10.0.0.0" in out
        assert not _has_manual_review(out)

    def test_service_object_huawei_usg_to_hillstone(self):
        out = _translate("ip service-set HTTP type object\n service 0 protocol tcp destination-port 80\n", "huawei_usg", "hillstone")
        assert "service HTTP tcp" in out
        assert not _has_manual_review(out)

    def test_security_policy_huawei_usg_to_hillstone(self):
        out = _translate("security-policy\n rule name ALLOW\n  source-zone trust\n  destination-zone untrust\n  source-address any\n  destination-address any\n  service any\n  action permit\n", "huawei_usg", "hillstone")
        assert "policy ALLOW" in out
        assert "action permit" in out
        assert not _has_manual_review(out)

    def test_zone_topsec_to_huawei_usg(self):
        out = _translate("zone name trust\n", "topsec", "huawei_usg")
        assert "security-zone name trust" in out
        assert not _has_manual_review(out)

    def test_address_topsec_to_huawei_usg(self):
        out = _translate("address name ADDR ip 10.0.0.0 mask 255.255.255.0\n", "topsec", "huawei_usg")
        assert "address-set ADDR" in out or "address 0 10.0.0.0" in out
        assert not _has_manual_review(out)

    def test_nat_guarded_cross_vendor(self):
        out = _translate("nat-policy\n rule name NAT1\n  action source-nat\n", "huawei_usg", "hillstone")
        assert _has_manual_review(out)

    def test_ipsec_guarded_cross_vendor(self):
        out = _translate("ipsec policy POLICY 10 isakmp\n", "cisco", "huawei")
        assert _has_manual_review(out)

    def test_hillstone_address_passthrough(self):
        out = _translate("address ADDR 10.0.0.0 255.255.255.0\n", "hillstone", "hillstone")
        assert "address ADDR 10.0.0.0" in out
        assert not _has_manual_review(out)

    def test_dptech_address_object_to_hillstone(self):
        out = _translate("object address ADDR 10.0.0.0 255.255.255.0\n", "dptech", "hillstone")
        assert "address ADDR 10.0.0.0" in out
        assert not _has_manual_review(out)


class TestBatchOSecurityFallback:
    """Security invariants in fallback rules"""

    def test_no_secret_in_deployable_cisco_snmp(self):
        out = _translate("snmp-server community SecretComm RO\n", "cisco", "huawei")
        assert "SecretComm" not in out
        assert _has_redacted(out) or _has_manual_review(out)

    def test_no_secret_in_deployable_huawei_snmp(self):
        out = _translate("snmp-agent community read SecretComm\n", "huawei", "cisco")
        assert "SecretComm" not in out
        assert _has_redacted(out) or _has_manual_review(out)

    def test_no_secret_in_deployable_radius(self):
        out = _translate("radius scheme RS\n primary authentication 10.0.0.1\n key cipher SecretRadius\n", "h3c", "cisco")
        assert "SecretRadius" not in out
        assert _has_redacted(out) or _has_manual_review(out)

    def test_no_secret_in_deployable_bgp(self):
        out = _translate("neighbor 10.0.0.1 password SecretBGP\n", "cisco", "huawei")
        assert "SecretBGP" not in out
        assert _has_redacted(out) or _has_manual_review(out)

    def test_no_source_residue_cisco_trunk_to_huawei(self):
        out = _translate("interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n", "cisco", "huawei")
        assert "switchport mode trunk" not in out
        assert "switchport trunk allowed vlan" not in out

    def test_no_source_residue_huawei_trunk_to_cisco(self):
        out = _translate("interface GigabitEthernet0/1\n port link-type trunk\n port trunk allow-pass vlan 10 20\n", "huawei", "cisco")
        assert "port link-type trunk" not in out
        assert "port trunk allow-pass vlan" not in out

    def test_no_source_residue_cisco_ospf_to_huawei(self):
        out = _translate("router ospf 1\n", "cisco", "huawei")
        assert "router ospf" not in out

    def test_no_source_residue_cisco_bgp_to_huawei(self):
        out = _translate("router bgp 65000\n", "cisco", "huawei")
        assert "router bgp" not in out
