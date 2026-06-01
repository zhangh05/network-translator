# -*- coding: utf-8 -*-
"""80+ product breadth target for module graph recognition."""

from core.module_graph import build_module_graph
from core.module_graph.capability_taxonomy import PRODUCT_CAPABILITY_BASELINE, capability_coverage_report


def _features(config, vendor="huawei"):
    return {module.feature for module in build_module_graph(config, vendor=vendor).modules}


def test_product_capability_baseline_reaches_80_capabilities():
    assert len(PRODUCT_CAPABILITY_BASELINE) >= 80


def test_80_target_capabilities_are_all_probe_covered():
    report = capability_coverage_report()
    assert report["summary"]["total"] >= 80
    assert report["summary"]["missing"] == 0
    assert report["summary"]["partial"] == 0
    assert report["summary"]["covered"] == report["summary"]["total"]


def test_advanced_switch_modules_are_typed_manual_review():
    config = """private-vlan primary 100
#
gvrp
mvrp enable
#
ethernet oam enable
#
cfm md MD1 level 3
#
monitor session 1 source interface GigabitEthernet0/1
#
remote-probe vlan 999
#
ip device tracking
#
errdisable recovery cause bpduguard
"""
    features = _features(config, vendor="cisco")
    for feature in (
        "l2.private_vlan",
        "l2.gvrp",
        "l2.mvrp",
        "oam.ethernet",
        "oam.cfm",
        "monitor.span",
        "monitor.rspan",
        "l2.device_tracking",
        "l2.errdisable",
    ):
        assert feature in features


def test_advanced_router_modules_are_typed_manual_review():
    config = """ripng 1
#
ospf 1
 mpls traffic-eng area 0
#
router bgp 65000
 bgp confederation identifier 65000
 neighbor 10.0.0.2 route-reflector-client
 neighbor 10.0.0.2 maximum-prefix 1000
 neighbor 10.0.0.2 ttl-security hops 1
 bgp graceful-restart
#
pbr track TRACK1
#
pbr verify-availability enable
#
interface Tunnel10
 ipv6 address 2001:db8:1::1/64
 tunnel mode ipv6ip
#
interface Vlanif10
 vrrp vrid 1 track interface GigabitEthernet0/0/1 reduced 30
#
acl number 3000
 rule 5 permit ip source object-group SRC destination any time-range WORK
#
ntp authentication-key 1 md5 SECRET
#
netconf ssh server enable
#
restconf
#
telemetry
#
ip flow-export destination 10.0.0.10 2055
#
interface GigabitEthernet0/0/1
 ip verify unicast reverse-path
"""
    features = _features(config, vendor="huawei")
    for feature in (
        "ripng.process",
        "ospf.te",
        "bgp.confederation",
        "bgp.route_reflector",
        "bgp.max_prefix",
        "bgp.gtsm",
        "bgp.graceful_restart",
        "pbr.track",
        "pbr.verify",
        "interface.tunnel6",
        "fhrp.track",
        "acl.object_group",
        "acl.time_range",
        "management.ntp_auth",
        "management.netconf",
        "management.restconf",
        "management.telemetry",
        "telemetry.flow",
        "security.urpf",
    ):
        assert feature in features


def test_advanced_firewall_modules_are_typed_manual_review():
    config = """proxy-policy
 rule name web-proxy
#
dns-filter profile DNS-PROTECT
#
mail-filter profile MAIL-PROTECT
#
file-blocking profile FILE-BLOCK
#
sandbox profile CLOUD-SANDBOX
#
decryption-policy
 rule name ssl-decrypt
#
hrp enable
#
virtual-system vsys1
#
firewall routing-instance VRF1
"""
    features = _features(config, vendor="huawei_usg")
    for feature in (
        "firewall.proxy",
        "firewall.dns_security",
        "firewall.mail_security",
        "firewall.file_blocking",
        "firewall.sandbox",
        "firewall.decryption",
        "firewall.ha",
        "firewall.vsys",
        "firewall.routing",
    ):
        assert feature in features
