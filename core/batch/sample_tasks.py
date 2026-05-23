"""Phase 8A: Sample batch tasks covering all domains and vendor pairs."""

from __future__ import annotations

from core.batch import BatchTask
from core.domain import DeviceDomain
from core.ir_models import IRConfig, IRConfigMeta
from core.ir_models.base import SourceSpan
from core.ir_models.common import IRAcl, IRAclEntry, IRStaticRoute
from core.ir_models.enums import IRType
from core.ir_models.firewall import IRAddressObject, IRSecurityPolicy, IRServiceObject, IRZone
from core.ir_models.router import IROspf
from core.ir_models.switch import IRLag, IRSvi, IRVlan
from core.renderer.base import RenderResult


def _span():
    return SourceSpan(1, 1, ["line"])


def _meta(src_vendor: str, tgt_vendor: str, domain: str) -> IRConfigMeta:
    return IRConfigMeta(
        source_vendor=src_vendor, target_vendor=tgt_vendor,
        source_domain=DeviceDomain(domain), target_domain=DeviceDomain(domain),
        source_platform=src_vendor, target_platform=tgt_vendor,
    )


def _rr(features: list[str]) -> RenderResult:
    return RenderResult(config_text="!\n", features_rendered=features)


# --- SWITCH tasks ---

SWITCH_TASKS: list[BatchTask] = [
    BatchTask(
        name="h3c_to_cisco_vlan_svi_acl",
        source_vendor="h3c", target_vendor="cisco", domain="switch",
        ir=IRConfig(
            meta=_meta("h3c", "cisco", "switch"),
            vlans=[IRVlan(IRType.VLAN, _span(), vid=10, name="MGMT"),
                   IRVlan(IRType.VLAN, _span(), vid=20, name="DATA")],
            svis=[IRSvi(IRType.SVI, _span(), vid=10, ip="10.0.0.1", mask="255.255.255.0"),
                  IRSvi(IRType.SVI, _span(), vid=20, ip="10.0.0.2", mask="255.255.255.0")],
            acls=[IRAcl(IRType.ACL, _span(), acl_type="extended", number=3050,
                        entries=[IRAclEntry("permit", sequence=5, protocol="tcp")])],
            static_routes=[IRStaticRoute(IRType.STATIC_ROUTE, _span(),
                                         prefix="0.0.0.0", mask="0.0.0.0", nexthop="10.0.0.254")],
        ),
        render_result=_rr(["vlans", "svis", "acls", "static_routes"]),
    ),
    BatchTask(
        name="cisco_to_h3c_vlan",
        source_vendor="cisco", target_vendor="h3c", domain="switch",
        ir=IRConfig(
            meta=_meta("cisco", "h3c", "switch"),
            vlans=[IRVlan(IRType.VLAN, _span(), vid=100, name="USERS")],
            svis=[IRSvi(IRType.SVI, _span(), vid=100, ip="192.168.1.254")],
        ),
        render_result=_rr(["vlans", "svis"]),
    ),
    BatchTask(
        name="huawei_to_cisco_stp_lag",
        source_vendor="huawei", target_vendor="cisco", domain="switch",
        ir=IRConfig(
            meta=_meta("huawei", "cisco", "switch"),
            vlans=[IRVlan(IRType.VLAN, _span(), vid=10),
                   IRVlan(IRType.VLAN, _span(), vid=20)],
            lags=[IRLag(IRType.LAG, _span(), lag_id=1, member_ports=["G0/1", "G0/2"])],
        ),
        render_result=_rr(["vlans", "lags"]),
    ),
    BatchTask(
        name="ruijie_to_cisco_acl",
        source_vendor="ruijie", target_vendor="cisco", domain="switch",
        ir=IRConfig(
            meta=_meta("ruijie", "cisco", "switch"),
            acls=[IRAcl(IRType.ACL, _span(), acl_type="extended", number=100,
                        entries=[IRAclEntry("permit", sequence=10, protocol="ip")])],
        ),
        render_result=_rr(["acls"]),
    ),
    BatchTask(
        name="h3c_to_ruijie_vlan_static",
        source_vendor="h3c", target_vendor="ruijie", domain="switch",
        ir=IRConfig(
            meta=_meta("h3c", "ruijie", "switch"),
            vlans=[IRVlan(IRType.VLAN, _span(), vid=10)],
            static_routes=[IRStaticRoute(IRType.STATIC_ROUTE, _span(),
                                         prefix="0.0.0.0", mask="0.0.0.0", nexthop="10.0.0.1")],
        ),
        render_result=_rr(["vlans", "static_routes"]),
    ),
    BatchTask(
        name="huawei_to_h3c_basic_vlan",
        source_vendor="huawei", target_vendor="h3c", domain="switch",
        ir=IRConfig(
            meta=_meta("huawei", "h3c", "switch"),
            vlans=[IRVlan(IRType.VLAN, _span(), vid=5)],
        ),
        render_result=_rr(["vlans"]),
    ),
    BatchTask(
        name="cisco_to_huawei_svi_static",
        source_vendor="cisco", target_vendor="huawei", domain="switch",
        ir=IRConfig(
            meta=_meta("cisco", "huawei", "switch"),
            svis=[IRSvi(IRType.SVI, _span(), vid=10, ip="10.0.0.1")],
            static_routes=[IRStaticRoute(IRType.STATIC_ROUTE, _span(),
                                         prefix="172.16.0.0", mask="255.255.0.0", nexthop="10.0.0.254")],
        ),
        render_result=_rr(["svis", "static_routes"]),
    ),
    BatchTask(
        name="ruijie_to_h3c_empty",
        source_vendor="ruijie", target_vendor="h3c", domain="switch",
        ir=IRConfig(meta=_meta("ruijie", "h3c", "switch")),
        render_result=_rr([]),
    ),
]

# --- ROUTER tasks ---

ROUTER_TASKS: list[BatchTask] = [
    BatchTask(
        name="h3c_to_huawei_ospf_deep",
        source_vendor="h3c", target_vendor="huawei", domain="router",
        ir=IRConfig(
            meta=_meta("h3c", "huawei", "router"),
            ospf=[IROspf(IRType.OSPF, _span(), process_id=1,
                         networks=[{"network": "10.0.0.0", "mask": "0.0.0.255", "area": "0"}],
                         areas=[{"area_id": "0", "type": "normal"}])],
            static_routes=[IRStaticRoute(IRType.STATIC_ROUTE, _span(),
                                         prefix="0.0.0.0", mask="0.0.0.0", nexthop="192.168.1.1")],
        ),
        render_result=_rr(["ospf", "static_routes"]),
    ),
    BatchTask(
        name="cisco_to_huawei_bgp_vrf",
        source_vendor="cisco", target_vendor="huawei", domain="router",
        ir=IRConfig(
            meta=_meta("cisco", "huawei", "router"),
            static_routes=[IRStaticRoute(IRType.STATIC_ROUTE, _span(),
                                         prefix="0.0.0.0", mask="0.0.0.0", nexthop="192.168.1.1")],
        ),
        render_result=_rr(["static_routes"]),
    ),
    BatchTask(
        name="huawei_to_cisco_ospf_mismatch",
        source_vendor="huawei", target_vendor="cisco", domain="router",
        ir=IRConfig(
            meta=_meta("huawei", "cisco", "router"),
            ospf=[IROspf(IRType.OSPF, _span(), process_id=1,
                         networks=[{"network": "10.0.0.0", "mask": "0.0.0.255", "area": "99"}],
                         areas=[{"area_id": "0", "type": "normal"}])],
            static_routes=[IRStaticRoute(IRType.STATIC_ROUTE, _span(),
                                         prefix="0.0.0.0", mask="0.0.0.0", nexthop="10.0.0.1")],
        ),
        render_result=_rr(["ospf", "static_routes"]),
    ),
    BatchTask(
        name="cisco_to_h3c_ospf_insufficient",
        source_vendor="cisco", target_vendor="h3c", domain="router",
        ir=IRConfig(
            meta=_meta("cisco", "h3c", "router"),
            ospf=[IROspf(IRType.OSPF, _span(), process_id=1)],
        ),
        render_result=_rr(["ospf"]),
    ),
    BatchTask(
        name="h3c_to_cisco_static_route",
        source_vendor="h3c", target_vendor="cisco", domain="router",
        ir=IRConfig(
            meta=_meta("h3c", "cisco", "router"),
            static_routes=[IRStaticRoute(IRType.STATIC_ROUTE, _span(),
                                         prefix="0.0.0.0", mask="0.0.0.0", nexthop="10.0.0.1")],
        ),
        render_result=_rr(["static_routes"]),
    ),
    BatchTask(
        name="ruijie_to_huawei_route_only",
        source_vendor="ruijie", target_vendor="huawei", domain="router",
        ir=IRConfig(
            meta=_meta("ruijie", "huawei", "router"),
            static_routes=[IRStaticRoute(IRType.STATIC_ROUTE, _span(),
                                         prefix="10.1.0.0", mask="255.255.0.0", nexthop="10.0.0.1")],
        ),
        render_result=_rr(["static_routes"]),
    ),
    BatchTask(
        name="huawei_vrp_to_cisco_router_basic",
        source_vendor="huawei", target_vendor="cisco", domain="router",
        ir=IRConfig(
            meta=_meta("huawei", "cisco", "router"),
            static_routes=[IRStaticRoute(IRType.STATIC_ROUTE, _span(),
                                         prefix="0.0.0.0", mask="0.0.0.0", nexthop="10.0.0.254")],
        ),
        render_result=_rr(["static_routes"]),
    ),
]

# --- FIREWALL tasks ---

FIREWALL_TASKS: list[BatchTask] = [
    BatchTask(
        name="huawei_usg_to_hillstone_basic",
        source_vendor="huawei_usg", target_vendor="hillstone", domain="firewall",
        ir=IRConfig(
            meta=_meta("huawei", "hillstone", "firewall"),
            zones=[IRZone(IRType.ZONE, _span(), name="trust"),
                   IRZone(IRType.ZONE, _span(), name="untrust")],
            address_objects=[IRAddressObject(IRType.ADDRESS_OBJECT, _span(),
                                             name="SRV1", ip="10.0.0.1")],
            service_objects=[IRServiceObject(IRType.SERVICE_OBJECT, _span(),
                                             name="HTTP", protocol="tcp", port="80")],
            security_policies=[IRSecurityPolicy(IRType.SECURITY_POLICY, _span(),
                                                name="allow-http", action="permit",
                                                from_zone="trust", to_zone="untrust")],
        ),
        render_result=_rr(["zones", "address_objects", "service_objects", "security_policies"]),
    ),
    BatchTask(
        name="hillstone_to_huawei_usg_empty",
        source_vendor="hillstone", target_vendor="huawei_usg", domain="firewall",
        ir=IRConfig(meta=_meta("hillstone", "huawei", "firewall")),
        render_result=_rr([]),
    ),
    BatchTask(
        name="topsec_to_hillstone_zones",
        source_vendor="topsec", target_vendor="hillstone", domain="firewall",
        ir=IRConfig(
            meta=_meta("topsec", "hillstone", "firewall"),
            zones=[IRZone(IRType.ZONE, _span(), name="inside"),
                   IRZone(IRType.ZONE, _span(), name="outside")],
            address_objects=[IRAddressObject(IRType.ADDRESS_OBJECT, _span(),
                                             name="SERVER", ip="192.168.1.100")],
        ),
        render_result=_rr(["zones", "address_objects"]),
    ),
    BatchTask(
        name="dptech_to_usg_policy",
        source_vendor="dptech", target_vendor="huawei_usg", domain="firewall",
        ir=IRConfig(
            meta=_meta("dptech", "huawei", "firewall"),
            zones=[IRZone(IRType.ZONE, _span(), name="lan"),
                   IRZone(IRType.ZONE, _span(), name="wan")],
            security_policies=[IRSecurityPolicy(IRType.SECURITY_POLICY, _span(),
                                                name="allow-dns",
                                                from_zone="lan", to_zone="wan")],
        ),
        render_result=_rr(["zones", "security_policies"]),
    ),
    BatchTask(
        name="usg_to_topsec_objects",
        source_vendor="huawei_usg", target_vendor="topsec", domain="firewall",
        ir=IRConfig(
            meta=_meta("huawei", "topsec", "firewall"),
            address_objects=[IRAddressObject(IRType.ADDRESS_OBJECT, _span(),
                                             name="NTP_POOL", ip="162.159.200.1")],
            service_objects=[IRServiceObject(IRType.SERVICE_OBJECT, _span(),
                                             name="NTP", protocol="udp", port="123")],
        ),
        render_result=_rr(["address_objects", "service_objects"]),
    ),
]

# --- ALL tasks combined ---

ALL_SAMPLE_TASKS: list[BatchTask] = (
    SWITCH_TASKS + ROUTER_TASKS + FIREWALL_TASKS
)

assert len(SWITCH_TASKS) == 8
assert len(ROUTER_TASKS) == 7
assert len(FIREWALL_TASKS) == 5
assert len(ALL_SAMPLE_TASKS) == 20
