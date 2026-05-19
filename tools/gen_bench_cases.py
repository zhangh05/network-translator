"""Generate 35+ benchmark cases for Step 21."""
import json, os

CASES_DIR = "bench/cases"

def write(name, case):
    d = os.path.join(CASES_DIR, case["source_domain"])
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, name + ".json")
    with open(path, "w") as f:
        json.dump(case, f, ensure_ascii=False, indent=2)
    print(f"  {path}")

# ── ROUTING (10) ────────────────────────────────────────────────
write("routing-01-interface-static", {
    "name": "h3c-routing-interface-static-to-cisco",
    "source_domain": "routing", "source_vendor": "h3c", "source_platform": "comware",
    "target_domain": "routing", "target_vendor": "cisco", "target_platform": "ios",
    "features": ["interface", "static_route"], "risk": "low",
    "source_config": """#
interface GigabitEthernet0/0
 description Uplink
 ip address 192.168.1.1 255.255.255.0
#
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.252
#
ip route-static 0.0.0.0 0.0.0.0 192.168.1.254
ip route-static 172.16.0.0 255.255.0.0 10.0.0.2""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["interface", "ip address", "ip route"],
        "must_not_include": ["ip route-static"],
        "max_level": "info"
    }
})

write("routing-02-ospf", {
    "name": "cisco-routing-ospf-to-huawei",
    "source_domain": "routing", "source_vendor": "cisco", "source_platform": "ios",
    "target_domain": "routing", "target_vendor": "huawei", "target_platform": "vrp",
    "features": ["ospf"], "risk": "medium",
    "source_config": """!
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
!
router ospf 100
 router-id 1.1.1.1
 network 192.168.1.0 0.0.0.255 area 0
 network 10.0.0.0 0.0.0.255 area 1
 default-information originate always
!""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["ospf", "area", "default-route-advertise"],
        "must_not_include": ["network 192", "wildcard"],
        "max_level": "info"
    }
})

write("routing-03-bgp-route-policy", {
    "name": "huawei-routing-bgp-route-policy-to-cisco",
    "source_domain": "routing", "source_vendor": "huawei", "source_platform": "vrp",
    "target_domain": "routing", "target_vendor": "cisco", "target_platform": "ios",
    "features": ["bgp", "route_policy"], "risk": "medium",
    "source_config": """#
bgp 65001
 router-id 2.2.2.2
 peer 192.168.1.2 as-number 65002
 peer 192.168.1.2 route-policy FROM_EBGP import
#
route-policy FROM_EBGP permit node 10
 if-match ip-prefix IMPORT
 apply local-preference 200
#
ip ip-prefix IMPORT permit 10.0.0.0 8 greater-equal 16 less-equal 24""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["route-map", "bgp", "neighbor", "set local-preference", "ip prefix-list"],
        "must_not_include": ["route-policy", "ip-prefix"],
        "max_level": "warning"
    }
})

write("routing-04-acl-pbr", {
    "name": "cisco-routing-acl-pbr-to-h3c",
    "source_domain": "routing", "source_vendor": "cisco", "source_platform": "ios",
    "target_domain": "routing", "target_vendor": "h3c", "target_platform": "comware",
    "features": ["acl", "pbr"], "risk": "medium",
    "source_config": """!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
!
ip access-list extended TRAFFIC-MATCH
 permit ip 192.168.1.0 0.0.0.255 any
!
route-map PBR permit 10
 match ip address TRAFFIC-MATCH
 set ip next-hop 10.0.0.254
!
interface GigabitEthernet0/0
 ip policy route-map PBR
!""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["policy-based-route", "if-match acl", "apply ip-address next-hop"],
        "must_not_include": ["route-map", "ip policy route-map"],
        "max_level": "warning"
    }
})

write("routing-05-vrf-static", {
    "name": "cisco-routing-vrf-static-to-huawei",
    "source_domain": "routing", "source_vendor": "cisco", "source_platform": "ios",
    "target_domain": "routing", "target_vendor": "huawei", "target_platform": "vrp",
    "features": ["vrf", "static_route"], "risk": "medium",
    "source_config": """!
ip vrf CUSTOMER-A
 rd 100:1
 route-target export 100:1
 route-target import 100:1
!
ip vrf CUSTOMER-B
 rd 100:2
!
interface GigabitEthernet0/0.100
 encapsulation dot1Q 100
 ip vrf forwarding CUSTOMER-A
 ip address 192.168.1.1 255.255.255.0
!
ip route vrf CUSTOMER-A 0.0.0.0 0.0.0.0 192.168.1.254
ip route vrf CUSTOMER-B 172.16.0.0 255.255.0.0 10.0.0.2
!""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["ip vpn-instance", "route-distinguisher", "ip binding vpn-instance", "ip route-static vpn-instance"],
        "must_not_include": ["ip vrf", "vrf forwarding", "route-target"],
        "max_level": "warning"
    }
})

write("routing-06-vrrp", {
    "name": "huawei-routing-vrrp-to-cisco",
    "source_domain": "routing", "source_vendor": "huawei", "source_platform": "vrp",
    "target_domain": "routing", "target_vendor": "cisco", "target_platform": "ios",
    "features": ["vrrp"], "risk": "low",
    "source_config": """#
interface GigabitEthernet0/0/1
 ip address 192.168.1.1 255.255.255.0
 vrrp vrid 1 virtual-ip 192.168.1.254
 vrrp vrid 1 priority 120
 vrrp vrid 1 preempt-mode timer delay 10
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["vrrp", "standby", "ip"],
        "must_not_include": ["vrid", "preempt-mode"],
        "max_level": "info"
    }
})

write("routing-07-dhcp", {
    "name": "cisco-routing-dhcp-to-h3c",
    "source_domain": "routing", "source_vendor": "cisco", "source_platform": "ios",
    "target_domain": "routing", "target_vendor": "h3c", "target_platform": "comware",
    "features": ["dhcp"], "risk": "low",
    "source_config": """!
ip dhcp excluded-address 192.168.1.1 192.168.1.10
ip dhcp pool LAN-POOL
 network 192.168.1.0 255.255.255.0
 default-router 192.168.1.254
 dns-server 8.8.8.8
 lease 7
!""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["dhcp", "network", "gateway-list"],
        "must_not_include": ["default-router", "ip dhcp pool"],
        "max_level": "info"
    }
})

write("routing-08-qos", {
    "name": "huawei-routing-qos-to-cisco",
    "source_domain": "routing", "source_vendor": "huawei", "source_platform": "vrp",
    "target_domain": "routing", "target_vendor": "cisco", "target_platform": "ios",
    "features": ["qos"], "risk": "medium",
    "source_config": """#
traffic classifier VOICE operator or
 if-match dscp ef
#
traffic behavior VOICE-MARK
 remark dscp ef
 queue ef 1000
#
traffic policy QOS-POLICY
 classifier VOICE behavior VOICE-MARK
#
interface GigabitEthernet0/0/1
 traffic-policy QOS-POLICY inbound
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["class-map", "policy-map", "service-policy", "priority"],
        "must_not_include": ["traffic classifier", "traffic behavior", "traffic-policy"],
        "max_level": "warning"
    }
})

write("routing-09-tunnel-gre", {
    "name": "cisco-routing-tunnel-to-huawei",
    "source_domain": "routing", "source_vendor": "cisco", "source_platform": "ios",
    "target_domain": "routing", "target_vendor": "huawei", "target_platform": "vrp",
    "features": ["tunnel"], "risk": "medium",
    "source_config": """!
interface Tunnel0
 ip address 10.255.255.1 255.255.255.252
 tunnel source GigabitEthernet0/0
 tunnel destination 203.0.113.1
 tunnel mode gre ip
 ip mtu 1400
 ip tcp adjust-mss 1360
 keepalive 10 3
!""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["interface Tunnel", "tunnel-protocol gre", "source", "destination"],
        "must_not_include": ["tunnel mode gre", "keepalive"],
        "max_level": "warning"
    }
})

write("routing-10-ospf-bfd", {
    "name": "h3c-routing-ospf-bfd-to-cisco",
    "source_domain": "routing", "source_vendor": "h3c", "source_platform": "comware",
    "target_domain": "routing", "target_vendor": "cisco", "target_platform": "ios",
    "features": ["ospf", "bfd"], "risk": "medium",
    "source_config": """#
bfd multi-hop min-transmit-interval 200 min-receive-interval 200 detect-multiplier 3
#
ospf 1 router-id 3.3.3.3
 area 0.0.0.0
  network 10.0.0.0 0.0.0.255
 bfd all-interfaces enable
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["bfd", "router ospf", "area"],
        "must_not_include": ["bfd all-interfaces enable"],
        "max_level": "warning"
    }
})

# ── SWITCHING (10) ─────────────────────────────────────────────
write("switching-01-vlan-access", {
    "name": "cisco-switching-vlan-access-to-h3c",
    "source_domain": "switching", "source_vendor": "cisco", "source_platform": "ios",
    "target_domain": "switching", "target_vendor": "h3c", "target_platform": "comware",
    "features": ["vlan"], "risk": "low",
    "source_config": """!
vlan 10
 name USERS
!
vlan 20
 name GUESTS
!
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
!
interface GigabitEthernet0/2
 switchport mode access
 switchport access vlan 20
!""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["vlan", "port access", "port link-type access"],
        "must_not_include": ["switchport mode access", "switchport access vlan"],
        "max_level": "info"
    }
})

write("switching-02-trunk", {
    "name": "h3c-switching-trunk-to-cisco",
    "source_domain": "switching", "source_vendor": "h3c", "source_platform": "comware",
    "target_domain": "switching", "target_vendor": "cisco", "target_platform": "ios",
    "features": ["trunk"], "risk": "low",
    "source_config": """#
interface GigabitEthernet1/0/1
 port link-type trunk
 port trunk permit vlan 10 20 30 100-200
 port trunk pvid vlan 10
#
interface GigabitEthernet1/0/2
 port link-type trunk
 port trunk permit vlan all
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["switchport mode trunk", "switchport trunk allowed vlan", "switchport trunk native vlan"],
        "must_not_include": ["port link-type trunk", "port trunk permit vlan"],
        "max_level": "info"
    }
})

write("switching-03-stp", {
    "name": "huawei-switching-stp-to-cisco",
    "source_domain": "switching", "source_vendor": "huawei", "source_platform": "vrp",
    "target_domain": "switching", "target_vendor": "cisco", "target_platform": "ios",
    "features": ["stp"], "risk": "medium",
    "source_config": """#
stp enable
stp mode mstp
stp region-configuration
 region-name CORE
 revision-level 1
 instance 1 vlan 10 20
 instance 2 vlan 30 40
 active region-configuration
#
interface GigabitEthernet0/0/1
 stp instance 1 priority 4096
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["spanning-tree", "mst", "instance", "vlan"],
        "must_not_include": ["stp enable", "stp mode", "region-configuration"],
        "max_level": "warning"
    }
})

write("switching-04-lacp-eth-trunk", {
    "name": "h3c-switching-lacp-to-cisco",
    "source_domain": "switching", "source_vendor": "h3c", "source_platform": "comware",
    "target_domain": "switching", "target_vendor": "cisco", "target_platform": "ios",
    "features": ["lacp"], "risk": "low",
    "source_config": """#
interface Bridge-Aggregation1
 port link-type trunk
 port trunk permit vlan 10 20 30
#
interface GigabitEthernet1/0/1
 port link-aggregation group 1
#
interface GigabitEthernet1/0/2
 port link-aggregation group 1
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["channel-group", "interface Port-channel", "switchport mode trunk"],
        "must_not_include": ["Bridge-Aggregation", "link-aggregation"],
        "max_level": "info"
    }
})

write("switching-05-switching-acl", {
    "name": "cisco-switching-acl-to-huawei",
    "source_domain": "switching", "source_vendor": "cisco", "source_platform": "ios",
    "target_domain": "switching", "target_vendor": "huawei", "target_platform": "vrp",
    "features": ["acl"], "risk": "medium",
    "source_config": """!
access-list 101 permit tcp 192.168.1.0 0.0.0.255 any eq 80
access-list 101 deny ip 192.168.2.0 0.0.0.255 any
!
interface GigabitEthernet0/1
 ip access-group 101 in
!""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["acl", "traffic-filter"],
        "must_not_include": ["ip access-group", "access-list 101"],
        "max_level": "warning"
    }
})

write("switching-06-qos", {
    "name": "huawei-switching-qos-to-h3c",
    "source_domain": "switching", "source_vendor": "huawei", "source_platform": "vrp",
    "target_domain": "switching", "target_vendor": "h3c", "target_platform": "comware",
    "features": ["qos"], "risk": "medium",
    "source_config": """#
traffic classifier VIDEO operator or
 if-match dscp af41
#
traffic behavior VIDEO-QOS
 remark dscp af41
 car cir 10000 pir 20000 cbs 2000000 pbs 4000000
#
traffic policy SWITCH-POLICY
 classifier VIDEO behavior VIDEO-QOS
#
interface GigabitEthernet0/0/1
 traffic-policy SWITCH-POLICY inbound
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["traffic classifier", "traffic behavior", "traffic policy", "car cir"],
        "must_not_include": ["class-map", "policy-map"],  # same-family, expect similar syntax
        "max_level": "warning"
    }
})

write("switching-07-lldp", {
    "name": "cisco-switching-lldp-to-huawei",
    "source_domain": "switching", "source_vendor": "cisco", "source_platform": "ios",
    "target_domain": "switching", "target_vendor": "huawei", "target_platform": "vrp",
    "features": ["lldp"], "risk": "low",
    "source_config": """!
lldp run
lldp timer 30
lldp holdtime 120
lldp reinit 2
!
interface GigabitEthernet0/1
 lldp transmit
 lldp receive
!
interface GigabitEthernet0/2
 no lldp transmit
 no lldp receive
!""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["lldp enable", "lldp"],
        "must_not_include": ["lldp reinit"],
        "max_level": "info"
    }
})

write("switching-08-cdp", {
    "name": "cisco-switching-cdp-to-huawei",
    "source_domain": "switching", "source_vendor": "cisco", "source_platform": "ios",
    "target_domain": "switching", "target_vendor": "huawei", "target_platform": "vrp",
    "features": ["cdp"], "risk": "low",
    "source_config": """!
cdp run
cdp timer 60
cdp holdtime 180
!
interface GigabitEthernet0/1
 cdp enable
!
interface GigabitEthernet0/2
 no cdp enable
!""",
    "expected": {
        "deployable": False, "manual_review_required": True,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["MANUAL_REVIEW", "CDP"],
        "must_not_include": ["<cdp", "TODO", "PLACEHOLDER"],
        "max_level": "warning"
    }
})

write("switching-09-stack", {
    "name": "h3c-switching-stack-to-cisco",
    "source_domain": "switching", "source_vendor": "h3c", "source_platform": "comware",
    "target_domain": "switching", "target_vendor": "cisco", "target_platform": "ios",
    "features": ["stack"], "risk": "medium",
    "source_config": """#
irf-port 1/1
 port group interface GigabitEthernet1/0/1
 port group interface GigabitEthernet1/0/2
#
irf-port 2/2
 port group interface GigabitEthernet2/0/1
 port group interface GigabitEthernet2/0/2
#
irf mac-address persistent always
irf auto-update enable
#""",
    "expected": {
        "deployable": False, "manual_review_required": True,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["MANUAL_REVIEW", "stack"],
        "must_not_include": ["<irf", "TODO", "PLACEHOLDER"],
        "max_level": "warning"
    }
})

write("switching-10-interface-basics", {
    "name": "huawei-switching-interface-to-h3c",
    "source_domain": "switching", "source_vendor": "huawei", "source_platform": "vrp",
    "target_domain": "switching", "target_vendor": "h3c", "target_platform": "comware",
    "features": ["interface"], "risk": "low",
    "source_config": """#
interface GigabitEthernet0/0/1
 description Link-to-Core
 undo shutdown
#
interface GigabitEthernet0/0/2
 description Link-to-DMZ
 shutdown
#
interface GigabitEthernet0/0/48
 description Trunk-to-Server
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["description", "undo shutdown"],
        "must_not_include": ["<interface", "TODO"],
        "max_level": "info"
    }
})

# ── FIREWALL (10) ──────────────────────────────────────────────
write("firewall-01-zone-address", {
    "name": "huawei-firewall-zone-address-to-cisco",
    "source_domain": "firewall", "source_vendor": "huawei", "source_platform": "vrp",
    "target_domain": "firewall", "target_vendor": "cisco", "target_platform": "asa",
    "features": ["zone", "address_object"], "risk": "medium",
    "source_config": """#
firewall zone trust
 set priority 85
 add interface GigabitEthernet0/0/1
#
firewall zone untrust
 set priority 5
 add interface GigabitEthernet0/0/2
#
ip address-set TRUST-LAN type object
 address 0 192.168.1.0 255.255.255.0
#
ip address-set DMZ-SERVER type object
 address 0 10.0.0.0 255.255.255.0
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["object-group", "subnet", "nameif", "security-level"],
        "must_not_include": ["ip address-set", "set priority"],
        "max_level": "warning"
    }
})

write("firewall-02-service-object", {
    "name": "h3c-firewall-service-object-to-huawei",
    "source_domain": "firewall", "source_vendor": "h3c", "source_platform": "comware",
    "target_domain": "firewall", "target_vendor": "huawei", "target_platform": "vrp",
    "features": ["service_object", "address_object"], "risk": "low",
    "source_config": """#
object service WEB
 service tcp destination-port eq 80 443
#
object service DNS
 service udp destination-port eq 53
#
object network VIP-SERVERS
 host 10.0.0.10 255.255.255.255
 host 10.0.0.11 255.255.255.255
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["ip address-set", "service-set"],
        "must_not_include": ["object service", "object network"],
        "max_level": "info"
    }
})

write("firewall-03-security-policy", {
    "name": "cisco-firewall-security-policy-to-h3c",
    "source_domain": "firewall", "source_vendor": "cisco", "source_platform": "asa",
    "target_domain": "firewall", "target_vendor": "h3c", "target_platform": "comware",
    "features": ["security_policy", "address_object", "service_object"], "risk": "high",
    "source_config": """!
object-group network LAN
 network-object 192.168.1.0 255.255.255.0
!
object-group network DMZ
 network-object 10.0.0.0 255.255.255.0
!
object-group service WEB
 service-object tcp-udp destination eq 80
 service-object tcp destination eq 443
!
access-list GLOBAL extended permit tcp object-group LAN object-group DMZ object-group WEB
access-list GLOBAL extended deny ip any any
!
access-group GLOBAL in interface inside
!""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["security-policy", "rule", "source-zone", "destination-zone"],
        "must_not_include": ["access-list GLOBAL", "object-group network"],
        "max_level": "warning"
    }
})

write("firewall-04-nat-source", {
    "name": "huawei-firewall-nat-source-to-cisco",
    "source_domain": "firewall", "source_vendor": "huawei", "source_platform": "vrp",
    "target_domain": "firewall", "target_vendor": "cisco", "target_platform": "asa",
    "features": ["nat"], "risk": "high",
    "source_config": """#
nat address-group NAT-POOL 0
 mode pat
 section 0 203.0.113.10 203.0.113.20
#
nat policy NAT-POLICY
 rule name SOURCE-NAT
  source-zone trust
  destination-zone untrust
  source-address 192.168.1.0 mask 255.255.255.0
  action source-nat address-group NAT-POOL
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["nat", "global", "inside"],
        "must_not_include": ["nat address-group", "nat policy"],
        "max_level": "warning"
    }
})

write("firewall-05-nat-server", {
    "name": "h3c-firewall-nat-server-to-huawei",
    "source_domain": "firewall", "source_vendor": "h3c", "source_platform": "comware",
    "target_domain": "firewall", "target_vendor": "huawei", "target_platform": "vrp",
    "features": ["nat", "zone", "address_object"], "risk": "high",
    "source_config": """#
interface GigabitEthernet1/0/1
 port link-mode route
 ip address 203.0.113.1 255.255.255.0
 nat server protocol tcp global 203.0.113.10 443 inside 10.0.0.10 443
 nat server protocol tcp global 203.0.113.10 80 inside 10.0.0.10 80
#
security-zone name Untrust
 import interface GigabitEthernet1/0/1
#
security-zone name Trust
 import interface GigabitEthernet1/0/2
#
object network WEB-SERVER
 ip address 10.0.0.10 255.255.255.255
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["nat server", "global", "inside"],
        "must_not_include": ["object network", "security-zone"],
        "max_level": "warning"
    }
})

write("firewall-06-acl", {
    "name": "cisco-firewall-acl-to-huawei",
    "source_domain": "firewall", "source_vendor": "cisco", "source_platform": "asa",
    "target_domain": "firewall", "target_vendor": "huawei", "target_platform": "vrp",
    "features": ["acl", "zone"], "risk": "medium",
    "source_config": """!
access-list INSIDE_IN extended permit tcp 192.168.1.0 255.255.255.0 any eq 80
access-list INSIDE_IN extended permit tcp 192.168.1.0 255.255.255.0 any eq 443
access-list INSIDE_IN extended deny ip any any
!
access-group INSIDE_IN in interface inside
!""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["acl", "traffic-filter", "rule"],
        "must_not_include": ["access-list INSIDE_IN", "access-group"],
        "max_level": "warning"
    }
})

write("firewall-07-ipsec", {
    "name": "cisco-firewall-ipsec-to-huawei",
    "source_domain": "firewall", "source_vendor": "cisco", "source_platform": "asa",
    "target_domain": "firewall", "target_vendor": "huawei", "target_platform": "vrp",
    "features": ["ipsec"], "risk": "high",
    "source_config": """!
crypto ikev1 policy 10
 authentication pre-share
 encryption aes-256
 hash sha
 group 14
 lifetime 86400
!
crypto ikev1 key CISCO123 address 203.0.113.2
!
crypto ipsec transform-set AES256-SHA esp-aes-256 esp-sha-hmac
 mode tunnel
!
crypto map CMAP 10 match address VPN-TRAFFIC
crypto map CMAP 10 set peer 203.0.113.2
crypto map CMAP 10 set transform-set AES256-SHA
crypto map CMAP interface outside
!""",
    "expected": {
        "deployable": True, "manual_review_required": True,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["ipsec", "ike", "proposal"],
        "must_not_include": ["<crypto", "TODO", "PLACEHOLDER"],
        "max_level": "warning"
    }
})

write("firewall-08-static-route", {
    "name": "h3c-firewall-static-route-to-cisco",
    "source_domain": "firewall", "source_vendor": "h3c", "source_platform": "comware",
    "target_domain": "firewall", "target_vendor": "cisco", "target_platform": "asa",
    "features": ["static_route", "interface"], "risk": "low",
    "source_config": """#
interface GigabitEthernet1/0/1
 ip address 203.0.113.1 255.255.255.0
#
ip route-static 0.0.0.0 0.0.0.0 203.0.113.254
ip route-static 192.168.0.0 255.255.0.0 10.0.0.2
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["route", "0.0.0.0"],
        "must_not_include": ["ip route-static", "TODO"],
        "max_level": "info"
    }
})

write("firewall-09-syslog", {
    "name": "cisco-firewall-syslog-to-huawei",
    "source_domain": "firewall", "source_vendor": "cisco", "source_platform": "asa",
    "target_domain": "firewall", "target_vendor": "huawei", "target_platform": "vrp",
    "features": ["syslog"], "risk": "low",
    "source_config": """!
logging enable
logging host inside 192.168.1.100
logging trap informational
logging source-interface inside
logging timestamp
!""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["info-center", "loghost"],
        "must_not_include": ["logging host", "logging trap"],
        "max_level": "info"
    }
})

write("firewall-10-security-policy-deny", {
    "name": "huawei-firewall-security-policy-deny-to-h3c",
    "source_domain": "firewall", "source_vendor": "huawei", "source_platform": "vrp",
    "target_domain": "firewall", "target_vendor": "h3c", "target_platform": "comware",
    "features": ["security_policy", "zone", "address_object"], "risk": "medium",
    "source_config": """#
firewall zone trust
 set priority 85
#
zone name DMZ
 set priority 50
#
security-policy
 rule name TRUST-TO-DMZ
  source-zone trust
  destination-zone DMZ
  source-address 192.168.1.0 mask 255.255.255.0
  destination-address 10.0.0.0 mask 255.255.255.0
  action permit
 rule name DENY-ALL
  source-zone trust
  destination-zone DMZ
  action deny
#""",
    "expected": {
        "deployable": True, "manual_review_required": False,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["security-policy", "rule", "action"],
        "must_not_include": ["zone name", "set priority"],
        "max_level": "warning"
    }
})

# ── HIGH-RISK NEGATIVE (5) ────────────────────────────────────
write("negative-01-import-bgp-missing-as", {
    "name": "h3c-routing-import-bgp-missing-as-to-cisco",
    "source_domain": "routing", "source_vendor": "h3c", "source_platform": "comware",
    "target_domain": "routing", "target_vendor": "cisco", "target_platform": "ios",
    "features": ["bgp", "ospf"], "risk": "high",
    "source_config": """#
ospf 1
 import-route bgp
#
bgp 65001
 peer 10.0.0.2 as-number 65002
#""",
    "expected": {
        "deployable": False, "manual_review_required": True,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["MANUAL_REVIEW"],
        "must_not_include": ["<AS", "TODO", "PLACEHOLDER", "<"],
        "max_level": "warning"
    }
})

write("negative-02-nat-missing-zone", {
    "name": "h3c-firewall-nat-missing-zone-to-huawei",
    "source_domain": "firewall", "source_vendor": "h3c", "source_platform": "comware",
    "target_domain": "firewall", "target_vendor": "huawei", "target_platform": "vrp",
    "features": ["nat"], "risk": "high",
    "source_config": """#
interface GigabitEthernet1/0/1
 port link-mode route
 ip address 203.0.113.1 255.255.255.0
 nat outbound 2000 address-group NAT-POOL
#
acl number 2000
 rule 0 permit source 192.168.1.0 0.0.0.255
#""",
    "expected": {
        "deployable": False, "manual_review_required": True,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["MANUAL_REVIEW"],
        "must_not_include": ["<ACL", "TODO", "PLACEHOLDER", "<"],
        "max_level": "warning"
    }
})

write("negative-03-platform-mismatch", {
    "name": "huawei-switching-to-cisco-ios-no-vlan-database",
    "source_domain": "switching", "source_vendor": "huawei", "source_platform": "vrp",
    "target_domain": "switching", "target_vendor": "cisco", "target_platform": "ios",
    "features": ["vlan", "interface"], "risk": "high",
    "source_config": """#
vlan batch 10 20 30 100 to 200
#
interface GigabitEthernet0/0/1
 port link-type trunk
 port trunk allow-pass vlan 10 20 30
#""",
    "expected": {
        "deployable": False, "manual_review_required": True,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["MANUAL_REVIEW"],
        "must_not_include": ["<vlan", "TODO", "PLACEHOLDER", "<"],
        "max_level": "warning"
    }
})

write("negative-04-asa-unsupported-feature", {
    "name": "cisco-asa-unsupported-to-huawei",
    "source_domain": "firewall", "source_vendor": "cisco", "source_platform": "asa",
    "target_domain": "firewall", "target_vendor": "huawei", "target_platform": "vrp",
    "features": ["security_policy", "nat"], "risk": "high",
    "source_config": """!
object-group network INSIDE
 network-object 192.168.1.0 255.255.255.0
!
nat (inside,outside) source dynamic INSIDE interface
!
access-list GLOBAL extended permit icmp any any echo-reply
!
access-group GLOBAL in interface outside
!""",
    "expected": {
        "deployable": True, "manual_review_required": True,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["MANUAL_REVIEW"],
        "must_not_include": ["<OBJECT", "TODO", "PLACEHOLDER", "<"],
        "max_level": "warning"
    }
})

write("negative-05-ospf-incomplete", {
    "name": "cisco-routing-ospf-incomplete-to-h3c",
    "source_domain": "routing", "source_vendor": "cisco", "source_platform": "ios",
    "target_domain": "routing", "target_vendor": "h3c", "target_platform": "comware",
    "features": ["ospf"], "risk": "high",
    "source_config": """!
router ospf 1
 redistribute bgp 65001 subnets
 redistribute connected subnets
 default-information originate always metric 20
!
router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
!""",
    "expected": {
        "deployable": False, "manual_review_required": True,
        "no_markdown_fence": True, "no_placeholder": True,
        "must_include": ["MANUAL_REVIEW"],
        "must_not_include": ["<BGP", "TODO", "PLACEHOLDER", "<"],
        "max_level": "warning"
    }
})

print(f"\nAll cases generated in {CASES_DIR}/")
