"""Generate P1 knowledge .md files for core vendors."""
import os

KNOWLEDGE_DIR = "knowledge_data/domains"

VENDOR_MAP = {
    "huawei": {"name": "Huawei", "cli_prefix": "#"},
    "h3c": {"name": "H3C", "cli_prefix": "#"},
    "cisco": {"name": "Cisco", "cli_prefix": "!"},
}

FEATURES = {
    "aaa": {
        "domains": ["routing", "switching", "firewall"],
        "vendors": {"huawei", "h3c", "cisco"},
    },
    "tunnel": {
        "domains": ["routing"],
        "vendors": {"huawei", "h3c", "cisco"},
    },
    "snmp": {
        "domains": ["routing", "switching", "firewall"],
        "vendors": {"huawei", "h3c", "cisco"},
    },
    "ntp": {
        "domains": ["routing", "switching", "firewall"],
        "vendors": {"huawei", "h3c", "cisco"},
    },
    "lldp": {
        "domains": ["routing", "switching"],
        "vendors": {"huawei", "h3c", "cisco"},
    },
    "cdp": {
        "domains": ["routing", "switching"],
        "vendors": {"cisco"},
    },
    "qos": {
        "domains": ["routing", "switching"],
        "vendors": {"huawei", "h3c", "cisco"},
    },
    "pbr": {
        "domains": ["routing"],
        "vendors": {"huawei", "h3c", "cisco"},
    },
    "vrf": {
        "domains": ["routing"],
        "vendors": {"huawei", "h3c", "cisco"},
    },
    "bfd": {
        "domains": ["routing"],
        "vendors": {"huawei", "h3c", "cisco"},
    },
    "ssh": {
        "domains": ["routing", "switching", "firewall"],
        "vendors": {"huawei", "h3c", "cisco"},
    },
    "syslog": {
        "domains": ["routing", "switching", "firewall"],
        "vendors": {"huawei", "h3c", "cisco"},
    },
}


def _p(title, lines):
    return "\n".join([f"## {title}"] + ["```"] + lines + ["```"]) + "\n"


def _comment(vendor, text):
    pre = VENDOR_MAP[vendor]["cli_prefix"]
    return f"{pre} {text}"


def _aaa_knowledge(vendor, domain):
    v = VENDOR_MAP[vendor]["name"]
    d = domain.capitalize()
    lines = [
        f"# {v} AAA Configuration ({d} Domain)",
        f"",
    ]
    if vendor == "cisco":
        lines += [
            "## Local Authentication",
            "```",
            "username <name> privilege <level> secret <password>",
            "aaa new-model",
            "aaa authentication login default local",
            "aaa authorization exec default local",
            "```",
            "",
            "## TACACS+",
            "```",
            "tacacs-server host <ip> key <key>",
            "aaa authentication login default group tacacs+ local",
            "aaa authorization exec default group tacacs+ local",
            "aaa accounting exec default start-stop group tacacs+",
            "```",
            "",
            "## RADIUS",
            "```",
            "radius-server host <ip> key <key>",
            "aaa authentication login default group radius local",
            "aaa authorization exec default group radius local",
            "aaa accounting exec default start-stop group radius",
            "```",
        ]
    elif vendor == "huawei":
        lines += [
            "## Local Authentication",
            "```",
            "aaa",
            " local-user <name> password irreversible-cipher <password>",
            " local-user <name> privilege level <level>",
            " local-user <name> service-type terminal telnet ssh",
            " quit",
            "```",
            "",
            "## RADIUS",
            "```",
            "radius-server template <name>",
            " radius-server shared-key-cipher <key>",
            " radius-server authentication <ip> <port>",
            " radius-server accounting <ip> <port>",
            " quit",
            "aaa",
            " authentication-scheme <name>",
            "  authentication-mode radius",
            " accounting-scheme <name>",
            "  accounting-mode radius",
            " domain <name>",
            "  authentication-scheme <name>",
            "  accounting-scheme <name>",
            "  radius-server <name>",
            "```",
        ]
    else:
        lines += [
            "## Local Authentication",
            "```",
            "local-user <name> class manage",
            " password hash <hash>",
            " authorization-attribute user-role network-admin",
            " service-type ssh telnet terminal",
            "```",
            "",
            "## RADIUS",
            "```",
            "radius scheme <name>",
            " primary authentication <ip>",
            " primary accounting <ip>",
            " key authentication cipher <key>",
            " key accounting cipher <key>",
            " user-name-format without-domain",
            " domain <name>",
            " authentication default radius-scheme <name>",
            " authorization default radius-scheme <name>",
            " accounting default radius-scheme <name>",
            "```",
        ]
    return "\n".join(lines) + "\n"


def _snmp_knowledge(vendor, domain):
    v = VENDOR_MAP[vendor]["name"]
    d = domain.capitalize()
    lines = [
        f"# {v} SNMP Configuration ({d} Domain)",
        f"",
    ]
    if vendor == "cisco":
        lines += [
            "## SNMPv2c",
            "```",
            _comment(vendor, "Read-only community"),
            "snmp-server community <string> ro",
            _comment(vendor, "Read-write community"),
            "snmp-server community <string> rw",
            _comment(vendor, "ACL restriction"),
            "snmp-server community <string> ro <acl-name>",
            _comment(vendor, "Trap destination"),
            "snmp-server enable traps",
            "snmp-server host <ip> version 2c <community>",
            "snmp-server location <text>",
            "snmp-server contact <text>",
            "```",
            "",
            "## SNMPv3",
            "```",
            "snmp-server group <group> v3 priv read <view> write <view>",
            "snmp-server user <user> <group> v3 auth sha <key> priv aes 256 <key>",
            _comment(vendor, "Trap with SNMPv3"),
            "snmp-server enable traps",
            "snmp-server host <ip> version 3 priv <user>",
            "```",
        ]
    elif vendor == "huawei":
        lines += [
            "## SNMPv2c",
            "```",
            "snmp-agent",
            "snmp-agent community read <string>",
            "snmp-agent community write <string>",
            "snmp-agent sys-info location <text>",
            "snmp-agent sys-info contact <text>",
            "snmp-agent trap enable",
            "snmp-agent target-host trap address udp-domain <ip> params securityname <community> v2c",
            "```",
            "",
            "## SNMPv3",
            "```",
            "snmp-agent sys-info version v3",
            "snmp-agent group v3 <group> privacy",
            "snmp-agent usm-user v3 <user> <group>",
            "  authentication-mode sha <key>",
            "  privacy-mode aes256 <key>",
            "snmp-agent target-host trap address udp-domain <ip> params securityname <user> v3 privacy",
            "```",
        ]
    else:
        lines += [
            "## SNMPv2c",
            "```",
            "snmp-agent",
            "snmp-agent community read <string>",
            "snmp-agent community write <string>",
            "snmp-agent sys-info location <text>",
            "snmp-agent sys-info contact <text>",
            "snmp-agent trap enable",
            "snmp-agent target-host trap address udp-domain <ip> params securityname <community>",
            "snmp-agent target-host trap address udp-domain <ip> params securityname <community_v3> v3",
            "```",
            "",
            "## SNMPv3",
            "```",
            "snmp-agent sys-info version v3",
            "snmp-agent group v3 <group> privacy",
            "snmp-agent usm-user v3 <user> <group> simple authentication-mode sha <key> privacy-mode aes128 <key>",
            "snmp-agent target-host trap address udp-domain <ip> params securityname <user> v3 privacy",
            "```",
        ]
    return "\n".join(lines) + "\n"


def _ntp_knowledge(vendor, domain):
    v = VENDOR_MAP[vendor]["name"]
    d = domain.capitalize()
    lines = [
        f"# {v} NTP Configuration ({d} Domain)",
        f"",
    ]
    if vendor == "cisco":
        lines += [
            "## Basic NTP",
            "```",
            "ntp server <ip> prefer",
            "ntp server <ip>",
            "ntp peer <ip>",
            "ntp source <interface-name>",
            "clock timezone <tz> <offset>",
            "ntp update-calendar",
            "```",
            "",
            "## NTP Authentication",
            "```",
            "ntp authenticate",
            "ntp authentication-key <id> md5 <key>",
            "ntp trusted-key <id>",
            "ntp server <ip> key <id>",
            "```",
            "",
            "## NTP Access Control",
            "```",
            "access-list <num> permit <network> <wildcard>",
            "ntp access-group peer <acl>",
            "ntp access-group serve <acl>",
            "```",
        ]
    elif vendor == "huawei":
        lines += [
            "## Basic NTP",
            "```",
            "ntp-service unicast-server <ip>",
            "ntp-service unicast-server <ip> prefer",
            "ntp-service unicast-peer <ip>",
            "ntp-service source-interface <interface>",
            "clock timezone <tz> add <offset>",
            "```",
            "",
            "## NTP Authentication",
            "```",
            "ntp-service authentication enable",
            "ntp-service authentication-keyid <id> authentication-mode md5 <key>",
            "ntp-service reliable authentication-keyid <id>",
            "ntp-service unicast-server <ip> authentication-keyid <id>",
            "```",
        ]
    else:
        lines += [
            "## Basic NTP",
            "```",
            "ntp-service unicast-server <ip>",
            "ntp-service unicast-server <ip> priority",
            "ntp-service unicast-peer <ip>",
            "ntp-service source-interface <interface>",
            "clock timezone <tz> add <offset>",
            "```",
            "",
            "## NTP Authentication",
            "```",
            "ntp-service authentication enable",
            "ntp-service authentication-keyid <id> authentication-mode md5 <key>",
            "ntp-service reliable authentication-keyid <id>",
            "ntp-service unicast-server <ip> authentication-keyid <id>",
            "```",
        ]
    return "\n".join(lines) + "\n"


def _syslog_knowledge(vendor, domain):
    v = VENDOR_MAP[vendor]["name"]
    d = domain.capitalize()
    lines = [
        f"# {v} Syslog/Log Configuration ({d} Domain)",
        f"",
    ]
    if vendor == "cisco":
        lines += [
            "## Logging to Remote Server",
            "```",
            "logging host <ip>",
            "logging host <ip> transport udp <port>",
            "logging host <ip> transport tcp <port>",
            _comment(vendor, "Set logging severity (0-7)"),
            "logging trap <level>",
            "logging source-interface <interface>",
            "logging on",
            "logging buffered <size>",
            "logging console <level>",
            "logging monitor <level>",
            "```",
            "",
            "## Timestamp",
            "```",
            "service timestamps log datetime msec localtime show-timezone",
            "service timestamps debug datetime msec localtime show-timezone",
            "```",
        ]
    elif vendor == "huawei":
        lines += [
            "## Logging to Remote Server",
            "```",
            "info-center enable",
            "info-center loghost <ip>",
            "info-center loghost <ip> channel <id> facility <level>",
            "info-center loghost <ip> transport tcp",
            "info-center source default channel loghost log level informational",
            "info-center timestamp log {date | short | millisecond}",
            "```",
            "",
            "## Log Output",
            "```",
            "info-center console channel <id>",
            "info-center monitor channel <id>",
            "info-center logbuffer size <size>",
            "info-center logbuffer channel <id>",
            "```",
        ]
    else:
        lines += [
            "## Logging to Remote Server",
            "```",
            "info-center enable",
            "info-center loghost <ip>",
            "info-center loghost <ip> port <port>",
            "info-center loghost <ip> facility <level>",
            "info-center timestamp log {date | short | millisecond}",
            "```",
            "",
            "## Log Output",
            "```",
            "info-center console channel <id>",
            "info-center monitor channel <id>",
            "info-center logbuffer size <size>",
            "```",
        ]
    return "\n".join(lines) + "\n"


def _ssh_knowledge(vendor, domain):
    v = VENDOR_MAP[vendor]["name"]
    d = domain.capitalize()
    lines = [
        f"# {v} SSH Configuration ({d} Domain)",
        f"",
    ]
    if vendor == "cisco":
        lines += [
            "## SSH Server",
            "```",
            "hostname <name>",
            "ip domain-name <domain>",
            "crypto key generate rsa modulus <2048|4096>",
            "ip ssh version 2",
            "ip ssh authentication-retries <num>",
            "ip ssh time-out <seconds>",
            "line vty 0 15",
            " transport input ssh",
            " login local",
            "```",
        ]
    elif vendor == "huawei":
        lines += [
            "## SSH Server",
            "```",
            "rsa local-key-pair create",
            "stelnet server enable",
            "ssh server port <port>",
            "ssh server authentication-retries <num>",
            "ssh server timeout <minutes>",
            "user-interface vty 0 4",
            " authentication-mode aaa",
            " protocol inbound ssh",
            "```",
        ]
    else:
        lines += [
            "## SSH Server",
            "```",
            "public-key local create rsa",
            "ssh server enable",
            "ssh server port <port>",
            "ssh server authentication-retries <num>",
            "ssh server timeout <minutes>",
            "line vty 0 63",
            " authentication-mode scheme",
            " protocol inbound ssh",
            "user-role network-admin",
            "```",
        ]
    return "\n".join(lines) + "\n"


def _lldp_knowledge(vendor, domain):
    v = VENDOR_MAP[vendor]["name"]
    d = domain.capitalize()
    lines = [
        f"# {v} LLDP Configuration ({d} Domain)",
        f"",
    ]
    if vendor == "cisco":
        lines += [
            "## Global LLDP",
            "```",
            "lldp run",
            "lldp timer <seconds>",
            "lldp holdtime <seconds>",
            "lldp reinit <seconds>",
            "lldp tlv-select <tlv-type>",
            "```",
            "",
            "## Interface LLDP",
            "```",
            "interface <interface>",
            " lldp transmit",
            " lldp receive",
            " lldp tlv-enable <tlv-type>",
            " no lldp transmit",
            " no lldp receive",
            "```",
        ]
    elif vendor == "huawei":
        lines += [
            "## Global LLDP",
            "```",
            "lldp enable",
            "lldp message-transmission interval <seconds>",
            "lldp message-transmission hold-multiplier <num>",
            "lldp reinit-delay <seconds>",
            "lldp tlv-enable <tlv-type>",
            "```",
            "",
            "## Interface LLDP",
            "```",
            "interface <interface>",
            " lldp enable",
            " lldp transmit",
            " lldp receive",
            " undo lldp enable",
            "```",
        ]
    else:
        lines += [
            "## Global LLDP",
            "```",
            "lldp global enable",
            "lldp timer tx-interval <seconds>",
            "lldp timer hold-multiplier <num>",
            "lldp timer reinit-delay <seconds>",
            "```",
            "",
            "## Interface LLDP",
            "```",
            "interface <interface>",
            " lldp enable",
            "```",
        ]
    return "\n".join(lines) + "\n"


def _cdp_knowledge(vendor, domain):
    v = VENDOR_MAP[vendor]["name"]
    d = domain.capitalize()
    lines = [
        f"# {v} CDP Configuration ({d} Domain)",
        f"",
        "## Global CDP",
        "```",
        "cdp run",
        "cdp timer <seconds>",
        "cdp holdtime <seconds>",
        "cdp advertise-v2",
        "```",
        "",
        "## Interface CDP",
        "```",
        "interface <interface>",
        " cdp enable",
        " no cdp enable",
        "```",
    ]
    return "\n".join(lines) + "\n"


def _qos_knowledge(vendor, domain):
    v = VENDOR_MAP[vendor]["name"]
    d = domain.capitalize()
    lines = [
        f"# {v} QoS Configuration ({d} Domain)",
        f"",
    ]
    if vendor == "cisco":
        lines += [
            "## Class-Map",
            "```",
            "class-map match-any <name>",
            " match ip dscp <value>",
            " match ip precedence <value>",
            " match access-group <acl>",
            " match protocol <protocol>",
            "```",
            "",
            "## Policy-Map",
            "```",
            "policy-map <name>",
            " class <class-name>",
            "  set ip dscp <value>",
            "  set ip precedence <value>",
            "  police <rate> <burst> conform-action transmit exceed-action drop",
            "  bandwidth <kbps>",
            "  priority <kbps>",
            "  shape average <rate>",
            "  queue-limit <packets>",
            " class class-default",
            "  fair-queue",
            "```",
            "",
            "## Service Policy",
            "```",
            "interface <interface>",
            " service-policy input <policy-name>",
            " service-policy output <policy-name>",
            "```",
            "",
            "## NBAR",
            "```",
            "ip nbar protocol-discovery",
            "interface <interface>",
            " ip nbar protocol-discovery",
            "```",
        ]
    elif vendor == "huawei":
        lines += [
            "## Traffic Classifier",
            "```",
            "traffic classifier <name> operator {and | or}",
            " if-match dscp <value>",
            " if-match ip-precedence <value>",
            " if-match acl <acl>",
            " if-match protocol <protocol>",
            "```",
            "",
            "## Traffic Behavior",
            "```",
            "traffic behavior <name>",
            " remark dscp <value>",
            " remark ip-precedence <value>",
            " car cir <rate> pir <rate> cbs <burst> pbs <burst>",
            "  green pass yellow pass red discard",
            " queue ef <bandwidth>",
            " queue af <bandwidth>",
            " queue wfq <weight>",
            " shaping <rate>",
            "```",
            "",
            "## Traffic Policy",
            "```",
            "traffic policy <name>",
            " classifier <classifier> behavior <behavior>",
            " interface <interface>",
            "  traffic-policy <policy> inbound",
            "  traffic-policy <policy> outbound",
            "```",
        ]
    else:
        lines += [
            "## Traffic Classifier",
            "```",
            "traffic classifier <name> operator {and | or}",
            " if-match dscp <value>",
            " if-match ip-precedence <value>",
            " if-match acl <acl>",
            " if-match protocol <protocol>",
            "```",
            "",
            "## Traffic Behavior",
            "```",
            "traffic behavior <name>",
            " remark dscp <value>",
            " remark ip-precedence <value>",
            " car cir <rate> pir <rate> cbs <burst> pbs <burst>",
            " queue ef <bandwidth>",
            " queue af <bandwidth>",
            " queue wfq <weight>",
            " shaping <rate>",
            "```",
            "",
            "## Traffic Policy",
            "```",
            "traffic policy <name>",
            " classifier <classifier> behavior <behavior>",
            "```",
            "",
            "## Apply",
            "```",
            "interface <interface>",
            " traffic-policy <policy> inbound",
            " traffic-policy <policy> outbound",
            "```",
        ]
    return "\n".join(lines) + "\n"


def _pbr_knowledge(vendor, domain):
    v = VENDOR_MAP[vendor]["name"]
    d = domain.capitalize()
    lines = [
        f"# {v} PBR Configuration ({d} Domain)",
        f"",
    ]
    if vendor == "cisco":
        lines += [
            "## Route-map PBR",
            "```",
            "route-map <name> permit <seq>",
            " match ip address <acl>",
            " match length <min> <max>",
            " set ip next-hop <ip>",
            " set ip next-hop verify-availability",
            " set ip next-hop <ip> <weight>",
            " set interface <interface>",
            " set ip default next-hop <ip>",
            "```",
            "",
            "## Apply to Interface",
            "```",
            "interface <interface>",
            " ip policy route-map <name>",
            "```",
            "",
            "## Local PBR",
            "```",
            "ip local policy route-map <name>",
            "```",
        ]
    elif vendor == "huawei":
        lines += [
            "## Policy-based Route",
            "```",
            "policy-based-route <name> permit node <seq>",
            " if-match acl <acl>",
            " if-match packet-length <min> <max>",
            " apply ip-address next-hop <ip>",
            " apply ip-address next-hop <ip> <weight>",
            " apply output-interface <interface>",
            " apply ip-address default next-hop <ip>",
            "```",
            "",
            "## Apply to Interface",
            "```",
            "interface <interface>",
            " ip policy-based-route <name>",
            "```",
            "",
            "## Local PBR",
            "```",
            "ip local policy-based-route <name>",
            "```",
        ]
    else:
        lines += [
            "## Policy-based Route",
            "```",
            "policy-based-route <name> permit node <seq>",
            " if-match acl <acl>",
            " if-match packet-length <min> <max>",
            " apply ip-address next-hop <ip>",
            " apply ip-address next-hop <ip> <weight>",
            " apply output-interface <interface>",
            " apply ip-address default next-hop <ip>",
            "```",
            "",
            "## Apply to Interface",
            "```",
            "interface <interface>",
            " ip policy-based-route <name>",
            "```",
        ]
    return "\n".join(lines) + "\n"


def _vrf_knowledge(vendor, domain):
    v = VENDOR_MAP[vendor]["name"]
    d = domain.capitalize()
    lines = [
        f"# {v} VRF Configuration ({d} Domain)",
        f"",
    ]
    if vendor == "cisco":
        lines += [
            "## VRF Definition",
            "```",
            "ip vrf <name>",
            " rd <rd-value>",
            " route-target export <rt-value>",
            " route-target import <rt-value>",
            "```",
            "",
            "## VRF-lite (no MPLS)",
            "```",
            "ip vrf <name>",
            " rd <rd-value>",
            "```",
            "",
            "## Assign VRF to Interface",
            "```",
            "interface <interface>",
            " ip vrf forwarding <name>",
            " ip address <ip> <mask>",
            "```",
            "",
            "## VRF Static Route",
            "```",
            "ip route vrf <name> <prefix> <mask> <next-hop>",
            "```",
        ]
    elif vendor == "huawei":
        lines += [
            "## VRF Definition",
            "```",
            "ip vpn-instance <name>",
            " ipv4-family",
            "  route-distinguisher <rd-value>",
            "  vpn-target <rt-value> export-extcommunity",
            "  vpn-target <rt-value> import-extcommunity",
            "```",
            "",
            "## Assign VRF to Interface",
            "```",
            "interface <interface>",
            " ip binding vpn-instance <name>",
            " ip address <ip> <mask>",
            "```",
            "",
            "## VRF Static Route",
            "```",
            "ip route-static vpn-instance <name> <prefix> <mask> <next-hop>",
            "```",
        ]
    else:
        lines += [
            "## VRF Definition",
            "```",
            "ip vpn-instance <name>",
            " route-distinguisher <rd-value>",
            " vpn-target <rt-value> export-extcommunity",
            " vpn-target <rt-value> import-extcommunity",
            "```",
            "",
            "## Assign VRF to Interface",
            "```",
            "interface <interface>",
            " ip binding vpn-instance <name>",
            " ip address <ip> <mask>",
            "```",
            "",
            "## VRF Static Route",
            "```",
            "ip route-static vpn-instance <name> <prefix> <mask> <next-hop>",
            "```",
        ]
    return "\n".join(lines) + "\n"


def _bfd_knowledge(vendor, domain):
    v = VENDOR_MAP[vendor]["name"]
    d = domain.capitalize()
    lines = [
        f"# {v} BFD Configuration ({d} Domain)",
        f"",
    ]
    if vendor == "cisco":
        lines += [
            "## BFD Parameters",
            "```",
            "bfd interval <ms> min_rx <ms> multiplier <num>",
            "```",
            "",
            "## BFD with OSPF",
            "```",
            "router ospf <pid>",
            " bfd all-interfaces",
            "```",
            "",
            "## BFD with BGP",
            "```",
            "router bgp <asn>",
            " bfd all-interfaces",
            " neighbor <ip> fall-over bfd",
            "```",
            "",
            "## BFD with Static Route",
            "```",
            "ip route <prefix> <mask> <next-hop> bfd",
            "ip route <prefix> <mask> <next-hop> bfd <source>",
            "```",
        ]
    elif vendor == "huawei":
        lines += [
            "## Global BFD",
            "```",
            "bfd",
            " quit",
            "```",
            "",
            "## BFD Session",
            "```",
            "bfd <name> bind peer-ip <ip>",
            " discriminator local <id>",
            " discriminator remote <id>",
            " min-tx-interval <ms>",
            " min-rx-interval <ms>",
            " detect-multiplier <num>",
            " commit",
            "```",
            "",
            "## BFD with OSPF",
            "```",
            "ospf <pid>",
            " bfd all-interfaces enable",
            "```",
            "",
            "## BFD with BGP",
            "```",
            "bgp <asn>",
            " peer <ip> bfd enable",
            "```",
            "",
            "## BFD with Static Route",
            "```",
            "ip route-static <prefix> <mask> <next-hop> track bfd-session <name>",
            "```",
        ]
    else:
        lines += [
            "## Global BFD",
            "```",
            "bfd multi-hop min-transmit-interval <ms> min-receive-interval <ms> detect-multiplier <num>",
            "```",
            "",
            "## BFD Session",
            "```",
            "bfd <name> peer-ip <ip>",
            " discriminator local <id>",
            " discriminator remote <id>",
            " min-transmit-interval <ms>",
            " min-receive-interval <ms>",
            " detect-multiplier <num>",
            " commit",
            "```",
            "",
            "## BFD with OSPF",
            "```",
            "ospf <pid>",
            " bfd all-interfaces enable",
            "```",
            "",
            "## BFD with BGP",
            "```",
            "bgp <asn>",
            " peer <ip> bfd enable",
            "```",
            "",
            "## BFD with Static Route",
            "```",
            "ip route-static <prefix> <mask> <next-hop> bfd enable",
            "```",
        ]
    return "\n".join(lines) + "\n"


def _tunnel_knowledge(vendor, domain):
    v = VENDOR_MAP[vendor]["name"]
    d = domain.capitalize()
    lines = [
        f"# {v} Tunnel/GRE Configuration ({d} Domain)",
        f"",
    ]
    if vendor == "cisco":
        lines += [
            "## GRE Tunnel",
            "```",
            "interface Tunnel<id>",
            " ip address <ip> <mask>",
            " tunnel source <interface-or-ip>",
            " tunnel destination <ip>",
            " tunnel mode gre ip",
            " ip mtu <bytes>",
            " ip tcp adjust-mss <bytes>",
            " keepalive <seconds> <retries>",
            "```",
            "",
            "## IP-in-IP Tunnel",
            "```",
            "interface Tunnel<id>",
            " ip address <ip> <mask>",
            " tunnel source <ip>",
            " tunnel destination <ip>",
            " tunnel mode ipip",
            "```",
            "",
            "## Tunnel with IPsec",
            "```",
            "crypto isakmp policy <id>",
            " encryption aes 256",
            " authentication pre-share",
            " group 14",
            "crypto isakmp key <key> address <peer-ip>",
            "crypto ipsec transform-set <name> esp-aes 256 esp-sha-hmac",
            " mode tunnel",
            "crypto ipsec profile <name>",
            " set transform-set <name>",
            "interface Tunnel<id>",
            " tunnel protection ipsec profile <name>",
            "```",
        ]
    elif vendor == "huawei":
        lines += [
            "## GRE Tunnel",
            "```",
            "interface Tunnel<id>",
            " ip address <ip> <mask>",
            " tunnel-protocol gre",
            " source <interface-or-ip>",
            " destination <ip>",
            " gre key <key>",
            " mtu <bytes>",
            " tcp adjust-mss <bytes>",
            "```",
            "",
            "## IP-in-IP Tunnel",
            "```",
            "interface Tunnel<id>",
            " ip address <ip> <mask>",
            " tunnel-protocol ipip",
            " source <ip>",
            " destination <ip>",
            "```",
        ]
    else:
        lines += [
            "## GRE Tunnel",
            "```",
            "interface Tunnel<id>",
            " ip address <ip> <mask>",
            " tunnel-protocol gre",
            " source <interface-or-ip>",
            " destination <ip>",
            " gre key <key>",
            " mtu <bytes>",
            " tcp mss <bytes>",
            "```",
            "",
            "## IP-in-IP Tunnel",
            "```",
            "interface Tunnel<id>",
            " ip address <ip> <mask>",
            " tunnel-protocol ipip",
            " source <ip>",
            " destination <ip>",
            "```",
        ]
    return "\n".join(lines) + "\n"


GENERATORS = {
    "aaa": _aaa_knowledge,
    "snmp": _snmp_knowledge,
    "ntp": _ntp_knowledge,
    "syslog": _syslog_knowledge,
    "ssh": _ssh_knowledge,
    "lldp": _lldp_knowledge,
    "cdp": _cdp_knowledge,
    "qos": _qos_knowledge,
    "pbr": _pbr_knowledge,
    "vrf": _vrf_knowledge,
    "bfd": _bfd_knowledge,
    "tunnel": _tunnel_knowledge,
}


def generate_all():
    count = 0
    for feature, meta in FEATURES.items():
        for domain in meta["domains"]:
            for vendor in sorted(meta["vendors"]):
                d = os.path.join(KNOWLEDGE_DIR, domain, vendor)
                os.makedirs(d, exist_ok=True)
                path = os.path.join(d, f"{feature}.md")
                if os.path.exists(path):
                    print(f"  SKIP (exists): {domain}/{vendor}/{feature}.md")
                    continue
                content = GENERATORS[feature](vendor, domain)
                with open(path, "w") as f:
                    f.write(content.lstrip("\n"))
                count += 1
                print(f"  CREATED: {domain}/{vendor}/{feature}.md")
    print(f"\nTotal created: {count}")


if __name__ == "__main__":
    generate_all()
