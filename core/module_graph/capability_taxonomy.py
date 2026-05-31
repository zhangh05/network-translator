from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class CapabilitySpec:
    """Product-document aligned capability breadth item."""

    capability_id: str
    domain: str
    product_area: str
    module_features: tuple[str, ...]
    default_action: str
    vendor_platforms: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


SWITCH_PLATFORMS = ("cisco_ios_xe", "h3c_comware", "huawei_vrp", "ruijie_rgos")
ROUTER_PLATFORMS = ("cisco_ios_xe", "h3c_comware", "huawei_vrp", "ruijie_rgos")
FIREWALL_PLATFORMS = ("huawei_usg", "hillstone_stoneos", "topsec_tos", "dptech_fw")


PRODUCT_CAPABILITY_BASELINE: tuple[CapabilitySpec, ...] = (
    CapabilitySpec(
        "system.management",
        "SWITCH",
        "Basic configuration and management",
        ("device_identity", "management.ntp", "management.logging", "management.snmp", "management.aaa"),
        "auto_subset",
        SWITCH_PLATFORMS + ROUTER_PLATFORMS,
        ("Cisco IOS XE configuration guides", "H3C configuration guides", "Huawei VRP configuration guides", "Ruijie RGOS configuration guide"),
        "Secrets and AAA policies remain manual review.",
    ),
    CapabilitySpec(
        "switch.vlan",
        "SWITCH",
        "Ethernet switching",
        ("vlan", "interface.svi"),
        "auto_subset",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "Cisco LAN Switching Configuration Guide", "H3C Layer 2 LAN Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
    ),
    CapabilitySpec(
        "switch.trunk_access",
        "SWITCH",
        "Ethernet switching",
        ("interface.physical", "interface.lag"),
        "auto_subset",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "Cisco LAN Switching Configuration Guide", "H3C Layer 2 LAN Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
    ),
    CapabilitySpec(
        "switch.lacp",
        "SWITCH",
        "Link aggregation",
        ("interface.lag", "interface.physical"),
        "auto_subset",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "H3C Layer 2 LAN Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
        "Member binding is tracked as module coupling.",
    ),
    CapabilitySpec(
        "switch.stp_mstp",
        "SWITCH",
        "STP/RSTP/MSTP",
        ("stp", "stp.mstp"),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "Cisco LAN Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
        "Edge-port subset can translate; MST regions and instance mapping require review.",
    ),
    CapabilitySpec(
        "switch.qinq",
        "SWITCH",
        "QinQ / VLAN mapping",
        ("l2.qinq",),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
    ),
    CapabilitySpec(
        "switch.voice_vlan",
        "SWITCH",
        "Voice VLAN",
        ("l2.voice_vlan",),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
    ),
    CapabilitySpec(
        "switch.lldp",
        "SWITCH",
        "Neighbor discovery",
        ("l2.lldp",),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Ruijie Ethernet Switching Configuration", "Cisco LAN Switching Configuration Guide", "Huawei Ethernet Switching Configuration Guide"),
    ),
    CapabilitySpec(
        "switch.mac_table",
        "SWITCH",
        "MAC table",
        ("l2.mac_table",),
        "manual_review",
        SWITCH_PLATFORMS,
        ("Huawei Ethernet Switching Configuration Guide", "Ruijie Ethernet Switching Configuration"),
    ),
    CapabilitySpec(
        "router.static_route",
        "ROUTER",
        "IP routing",
        ("static_route", "static_route.option"),
        "auto_subset",
        ROUTER_PLATFORMS,
        ("Cisco IOS XE IP Routing Configuration Guide", "H3C Layer 3 IP Routing Configuration Guide", "Huawei VRP IP Routing Configuration", "Ruijie IP Routing Configuration"),
    ),
    CapabilitySpec(
        "router.ospf",
        "ROUTER",
        "IP routing",
        ("ospf.process", "ospf.area", "ospf.network", "ospf.passive_interface", "ospf.authentication", "ospf.redistribute", "ospf.area_special", "ospf.interface_tuning"),
        "auto_subset",
        ROUTER_PLATFORMS,
        ("Cisco IOS XE IP Routing Configuration Guide", "Huawei VRP IP Routing Configuration", "Ruijie IP Routing Configuration"),
    ),
    CapabilitySpec(
        "router.bgp",
        "ROUTER",
        "IP routing",
        ("bgp.process", "bgp.neighbor", "bgp.network", "bgp.password", "bgp.policy", "bgp.redistribute", "bgp.attribute"),
        "auto_subset",
        ROUTER_PLATFORMS,
        ("Cisco IOS XE IP Routing Configuration Guide", "Huawei VRP IP Routing Configuration", "Ruijie IP Routing Configuration"),
    ),
    CapabilitySpec(
        "router.rip",
        "ROUTER",
        "IP routing",
        ("rip.process", "rip.network", "rip.unknown"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("H3C Layer 3 IP Routing Configuration Guide", "Ruijie IP Routing Configuration"),
    ),
    CapabilitySpec(
        "router.isis",
        "ROUTER",
        "IP routing",
        ("isis.process", "isis.network", "isis.unknown"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Huawei VRP IP Routing Configuration", "Ruijie IP Routing Configuration"),
    ),
    CapabilitySpec(
        "router.vrf",
        "ROUTER",
        "VPN/VRF",
        ("vrf",),
        "auto_subset",
        ROUTER_PLATFORMS,
        ("Cisco IOS XE IP Routing Configuration Guide", "Huawei VRP IP Routing Configuration", "Ruijie IP Routing Configuration"),
    ),
    CapabilitySpec(
        "router.route_policy",
        "ROUTER",
        "Routing policies",
        ("route_policy", "route_filter"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Ruijie IP Routing Configuration", "H3C ACL and QoS Configuration Guide", "Cisco IOS XE IP Routing Configuration Guide"),
    ),
    CapabilitySpec(
        "router.pbr",
        "ROUTER",
        "Policy-based routing",
        ("pbr.policy", "pbr.binding"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Ruijie IP Routing Configuration", "Cisco IOS XE IP Routing Configuration Guide"),
    ),
    CapabilitySpec(
        "router.multicast",
        "ROUTER",
        "Multicast",
        ("multicast", "multicast.interface"),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Ruijie Multicast Configuration", "H3C IP Multicast Configuration Guide"),
    ),
    CapabilitySpec(
        "router.bfd",
        "ROUTER",
        "Resilience",
        ("bfd.session",),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Ruijie Device Management Configuration", "Huawei VRP Reliability Configuration"),
    ),
    CapabilitySpec(
        "router.dhcp",
        "ROUTER",
        "IP services",
        ("dhcp.pool",),
        "manual_review",
        ROUTER_PLATFORMS,
        ("Ruijie Device Management Configuration", "Cisco IOS XE IP Addressing Services"),
    ),
    CapabilitySpec(
        "firewall.objects",
        "FIREWALL",
        "Objects",
        ("zone", "address_object", "service_object", "object_group", "object_group.member"),
        "auto_subset",
        FIREWALL_PLATFORMS,
        ("Huawei USG Quick Configuration Guide", "Hillstone StoneOS User Manual", "DPtech Firewall Technical White Paper"),
    ),
    CapabilitySpec(
        "firewall.policy",
        "FIREWALL",
        "Security policy",
        ("security_policy",),
        "auto_subset",
        FIREWALL_PLATFORMS,
        ("Huawei USG Quick Configuration Guide", "Hillstone StoneOS User Manual", "DPtech Firewall Technical White Paper", "Topsec Firewall product documentation"),
    ),
    CapabilitySpec(
        "firewall.nat",
        "FIREWALL",
        "NAT",
        ("firewall.nat",),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Huawei USG Quick Configuration Guide", "DPtech Firewall Technical White Paper", "Hillstone StoneOS User Manual"),
    ),
    CapabilitySpec(
        "firewall.ipsec",
        "FIREWALL",
        "IPsec / VPN",
        ("firewall.ipsec", "interface.tunnel"),
        "manual_review",
        FIREWALL_PLATFORMS,
        ("Huawei USG VPN Guide", "Hillstone StoneOS User Manual", "DPtech VPN Security Gateway Technical White Paper"),
    ),
    CapabilitySpec(
        "firewall.utm_profile",
        "FIREWALL",
        "UTM / application security",
        ("firewall.profile", "time_range"),
        "identify_only",
        FIREWALL_PLATFORMS,
        ("DPtech Firewall Technical White Paper", "Hillstone StoneOS product guide", "Huawei USG support guide"),
    ),
    CapabilitySpec(
        "acl_qos",
        "SWITCH",
        "ACL and QoS",
        ("acl", "acl_binding", "qos.classifier", "qos.behavior", "qos.policy", "qos.binding"),
        "auto_subset",
        SWITCH_PLATFORMS + ROUTER_PLATFORMS,
        ("H3C ACL and QoS Configuration Guide", "Cisco IOS XE QoS Configuration Guide", "Ruijie ACL and QoS Configuration"),
    ),
)


def baseline_by_domain() -> dict[str, list[CapabilitySpec]]:
    grouped: dict[str, list[CapabilitySpec]] = {}
    for spec in PRODUCT_CAPABILITY_BASELINE:
        grouped.setdefault(spec.domain, []).append(spec)
    return grouped


def known_module_features() -> set[str]:
    return {feature for spec in PRODUCT_CAPABILITY_BASELINE for feature in spec.module_features}


def capability_coverage_report() -> dict:
    covered_features = known_module_features()
    missing_capabilities = [
        spec.capability_id
        for spec in PRODUCT_CAPABILITY_BASELINE
        if not any(feature in covered_features for feature in spec.module_features)
    ]
    return {
        "summary": {
            "total": len(PRODUCT_CAPABILITY_BASELINE),
            "covered": len(PRODUCT_CAPABILITY_BASELINE) - len(missing_capabilities),
            "missing": len(missing_capabilities),
        },
        "missing_capabilities": missing_capabilities,
        "domains": {domain: [spec.to_dict() for spec in specs] for domain, specs in baseline_by_domain().items()},
    }
