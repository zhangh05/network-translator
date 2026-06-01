# Config Module Graph

This document records the module-decomposition layer introduced after the Beta
fallback hardening work.

## Goal

Large network configs should not be treated as one flat string. Before
translation, the source config can be decomposed into auditable modules:

- Device identity modules
- VLAN modules
- Interface modules split by kind
- ACL definition and ACL binding modules
- Routing modules such as static route, VRF, OSPF, BGP, and route-policy
- Resiliency/service modules such as BFD, FHRP/VRRP, DHCP pool, and tunnel
- Additional routing-control modules such as RIP, IS-IS, PBR, and multicast
- QoS and management-plane modules
- Firewall object and policy modules
- Manual-review modules for unsupported or vendor-specific features

Each module keeps the original source lines and line span. It can provide named
resources, consume named resources, depend on other modules, and expose typed
couplings such as "ACL binding uses interface" or "security policy uses object".

## Current Scope

The first implementation is intentionally additive:

- `core/module_graph/` builds a graph from existing feature blocks.
- `FallbackNode` stores the graph under `_fallback_metadata["module_graph"]`.
- `ParseNode` builds the graph for both LLM and fallback paths.
- API results expose `module_summary` and `module_graph`.
- Fallback results expose `module_translations` and `manual_review_config`.
- The manual-review UI can use module source lines, line spans, and dependency
  metadata as user-facing evidence.
- Existing parser, renderer, validator, fallback rules, project store, and UI
  behavior are not replaced.

This makes the next UI step straightforward: a dedicated "source modules /
manual-review evidence" view can show exactly which original lines need human
confirmation without polluting the translated configuration tab.

## Key Fields

`ConfigModule`:

- `module_id`: stable source-order identifier.
- `feature`: normalized feature type, for example `device_identity`, `vlan`,
  `interface.svi`, `interface.physical`, `acl`, `acl_binding`,
  `object_group`, `static_route`, `vrf`, `route_filter`, `route_policy`,
  `qos.policy`, `qos.binding`, `management.ntp`, `ospf.process`,
  `bgp.process`, `bfd.session`, `fhrp.vrrp`, `dhcp.pool`, `interface.tunnel`,
  `rip.process`, `isis.process`, `pbr.binding`,
  `multicast.interface`, `firewall.nat`, `firewall.ipsec`,
  `firewall.profile`, `time_range`, `zone`, `address_object`,
  `service_object`, `security_policy`, or `unknown`.
- `start_line` / `end_line`: original config line span.
- `source_lines`: original source config lines.
- `provides`: resources defined by the module, such as `vlan:10` or `acl:3000`.
- `consumes`: resources referenced by the module, such as `vlan:10` from an SVI
  or `acl:3000` from an interface ACL binding.
- `depends_on`: module ids that should be considered before this module.
- `tags`: lightweight hints such as `svi` or `trunk`.
- `couplings`: typed relation evidence attached to the consumer module.
- `status`: `translatable` or `manual_review`.
- `manual_review_reason`: user-facing reason when status is `manual_review`.

`ModuleDependency`:

- `from_module`: consumer module id.
- `to_module`: provider module id.
- `label`: resource key connecting the two modules.

`ModuleCoupling`:

- `from_module`: consumer module id.
- `to_module`: provider module id.
- `relation`: semantic relation, for example `interface_uses_vlan`,
  `binds_acl_to_interface`, `policy_uses_object`, or `member_of_lag`.
- `resource`: resource key behind the relation.

`AssemblyResult`:

- `sections`: dependency-ordered module sections.
- `text`: source modules rendered with audit headers. This is not target-vendor
  output. It is a deterministic source-order/dependency-order assembly view.

`ModuleTranslationResult`:

- `status`: `translated`, `partial`, `semantic_near`, `manual_review`, or
  `unsupported`.
- `translated_lines`: target-vendor lines that are trusted enough to enter
  `deployable_config`.
- `suggested_lines`: target-vendor-like lines shown only in the "配置语义相近"
  view. They are evidence for reviewer judgment, not deployable output.
- `manual_review_lines`: source evidence and reason comments for anything that
  still needs confirmation.

## Conservative Semantic-Near Layer

Some features are simple at the binding level but risky at the policy-body level.
For example, an interface-level QoS binding can be mapped by direction:

```text
traffic-policy SETDSCP outbound
```

can become:

```text
service-policy output SETDSCP
```

That binding is safe enough for `deployable_config`. The referenced QoS
classifier, behavior, and policy body are different: DSCP rewrite, policing,
queueing, matching mode, and default-class behavior can vary by platform. For
those modules the translator may produce `semantic_near` results with
`suggested_lines`, such as a `policy-map` skeleton, but those suggested lines
must not be merged into `deployable_config`.

This gives the UI three separate buckets:

- `deployable_config`: trusted target config only.
- "配置语义相近": source module + suggested target config + confirmation point.
- `manual_review_config`: source evidence when no safe suggestion exists.

`semantic_near` is intentionally conservative. It reduces blind manual review by
showing a likely target shape, but it still raises a review signal and keeps the
translation non-deployable until the reviewer confirms the module.

Current semantic-near families:

| Module family | Example source | Suggested target shape | Why not deployable |
|---|---|---|---|
| QoS policy body | `traffic policy` / `policy-map` | `policy-map` or `traffic policy` skeleton | classifier/action/default-class behavior can differ |
| Route policy | `route-policy` / `route-map` | match/set skeleton | match order, community, continue/call, and attribute side effects need review |
| BGP policy attachment | `peer ... route-policy` / `neighbor ... route-map` | peer/neighbor attachment skeleton | route direction and referenced policy semantics need review |
| Static route options | `track`, `bfd`, `tag`, `preference`, `description` | base route plus option warning | route liveness and preference behavior differs |
| FHRP | VRRP/HSRP VIP, priority, preempt | HSRP/VRRP group skeleton | preempt, track, timers, and active/standby behavior differ |
| DHCP relay | helper/server relay lines | helper/server-address skeleton | relay source, VRF, option-82, and server group behavior differ |
| LACP tuning | timeout, priority, preempt | LACP timer/priority skeleton | timer and preempt behavior affects convergence |
| MSTP region | region name, revision, instance VLAN map | MST configuration skeleton | region consistency affects topology and outage risk |
| Management SNMP/logging/NTP | community/loghost/server lines | redacted or host-only skeleton | secrets and management-plane policy need review |
| OSPF advanced | authentication, redistribute, stub/NSSA, interface tuning | authentication/redistribute/tuning skeleton | keys, area type, redistribution policy, and convergence behavior differ |
| RIP / IS-IS | process, network/NET, redistribute, metric style | process/network/redistribute skeleton | metric, level, auth, and redistribution behavior need review |
| Multicast | RP and interface PIM/IGMP lines | RP, PIM, and IGMP skeleton | ASM/SSM, RP/BSR, interface mode, and querier behavior differ |
| Access authentication | 802.1X, MAB, portal, radius domain, interface binding | AAA and interface access-session skeleton | fail action, critical VLAN, server groups, and auth order need review |
| Route filters / PBR | prefix-list, object/time ACL references, policy-based-route | prefix-list, route-map, and interface PBR skeleton | filter order, object model, next-hop fallback, and time conditions need review |
| IPv6 routing/services | IPv6 static route, interface IPv6, ND/RA, IPv6 ACL, OSPFv3/RIPng, DHCPv6 | IPv6 route/interface/ACL/protocol/relay skeleton | link-local, RA flags, DHCPv6 mode, address-family, and VRF behavior differ |
| Platform / Overlay | stack/IRF, VXLAN VNI, EVPN RT/RD | stackwise/IRF, VXLAN, and EVPN skeleton | member IDs, interface renumbering, VTEP, VNI, RT/RD direction, and gateway mode need review |
| BFD / MPLS / Segment Routing | BFD sessions, MPLS LDP/TE/L3VPN, SR binding | BFD template, MPLS, VRF, and SR skeleton | timers, labels, RD/RT, RSVP/SR policy, and IGP binding need review |
| SLA / Tunnel / DHCP / EIGRP | NQA/IP-SLA, GRE/IPv6 tunnel, DHCP pool, EIGRP | target-shaped probe, tunnel, DHCP, or source-preserving EIGRP redesign skeleton | probe track binding, tunnel encapsulation, DHCP options, and Cisco-specific EIGRP behavior need review |
| Advanced management / telemetry | SSH, PKI, AAA, NTP auth, NETCONF/RESTCONF, telemetry, flow export | redacted management/API/telemetry skeleton | credentials, RBAC, certificates, collectors, and exposed management surfaces need review |
| Advanced routing control | PBR track/verify, OSPF TE, MSDP, FHRP track, advanced BGP families | track, TE, MSDP, FHRP, address-family, and neighbor-control skeleton | liveness linkage, TE database, RP relation, failover, MP-BGP scope, and restart behavior need review |
| IPv6 first-hop security | ND snooping, IPv6 source guard, RA guard | ND inspection/source-verify/RA-guard skeleton | trust ports, binding sources, and router role policies need review |
| Advanced firewall services | NAT, IPsec, IPS/URL/AV/app profiles, HA, vsys | NAT/IPsec/profile/HA/vsys skeleton | no implicit any, engines/licensing, crypto, session sync, and policy binding need review |
| Firewall application services | SSL VPN, DoS/DLP/WAF, load balancing, proxy, SSL decryption, firewall routing | target-shaped service skeleton | certificate, engine, health-check, exception, privacy, and route-policy coupling need review |
| L2 security / resilience / OAM / monitoring | ERPS/RRPP, Smart Link, MLAG, PVLAN, VLAN mapping, DHCP snooping, source guard, ARP inspection, RSPAN, OAM, uRPF | target feature skeleton with confirmation points | trust boundaries, failure actions, thresholds, peer links, ring state, and traffic-copy behavior differ |

## Example

```text
vlan batch 10
#
acl number 3000
 rule 5 permit ip
#
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
 traffic-filter inbound acl 3000
```

The resulting graph contains:

- VLAN module provides `vlan:10`.
- ACL module provides `acl:3000`.
- SVI module provides `interface:Vlanif10` and consumes `vlan:10`.
- ACL binding module consumes `interface:Vlanif10` and `acl:3000`.
- Edges connect SVI -> VLAN and ACL binding -> SVI/ACL.
- Couplings record `interface_uses_vlan` and `binds_acl_to_interface`.

The source assembly view can render providers before the consumer:

```text
### module 0003:vlan:7 | feature=vlan | status=translatable | lines=7-7 | provides=vlan:10
vlan batch 10

### module 0002:acl:4 | feature=acl | status=translatable | lines=4-5 | provides=acl:3000
acl number 3000
 rule 5 permit ip

### module 0001:interface.svi:1 | feature=interface.svi | status=translatable | lines=1-3 | depends_on=0003:vlan:7 | provides=interface:Vlanif10 | consumes=vlan:10 | tags=svi
interface Vlanif10
ip address 10.0.10.1 255.255.255.0
traffic-filter inbound acl 3000

### module 0004:acl_binding:3 | feature=acl_binding | status=translatable | lines=3-3 | depends_on=0001:interface.svi:1,0002:acl:4 | consumes=acl:3000,interface:Vlanif10 | tags=inbound
traffic-filter inbound acl 3000
```

## Module Taxonomy

| Feature | Purpose | Typical provides | Typical consumes |
|---|---|---|---|
| `device_identity` | Hostname/sysname | `device:hostname` | none |
| `vlan` | VLAN definition | `vlan:10` | none |
| `interface.svi` | VLAN L3 interface | `interface:Vlanif10` | `vlan:10` |
| `interface.physical` | Physical port | `interface:GE0/0/1` | `vlan:*`, `lag:*` |
| `interface.lag` | Link aggregation interface | `interface:Eth-Trunk1`, `lag:1` | none |
| `interface.loopback` | Loopback interface | `interface:LoopBack0` | none |
| `interface.tunnel` | Tunnel/GRE/IPsec-like interface | `interface:Tunnel0/0/0`, `tunnel:Tunnel0/0/0` | `source:*`, `destination:*` |
| `acl` | ACL definition | `acl:3000` | optional `time-range:*`, `object-group:*` |
| `acl_binding` | ACL bind point | none | `acl:3000`, `interface:*` |
| `object_group` | Cisco/ASA-style object-group container | `object-group:WEB` | none |
| `object_group.member` | Object-group member line | none | `object-group:WEB` |
| `static_route` | Basic static route | `route:dst:mask:nexthop` | optional `vrf:*` |
| `static_route.option` | Static route with track/BFD/tag/description/preference | `route:dst:mask:nexthop` | optional `vrf:*` |
| `vrf` | VRF/VPN instance | `vrf:CUST-A` | route-target dependencies later |
| `ospf.process` | OSPF process and router-id | `ospf:1` | none |
| `ospf.area` | Plain OSPF area declaration | `ospf:1:area:0.0.0.0` | `ospf:1` |
| `ospf.network` | OSPF network statement | none | `ospf:1`, optional area |
| `ospf.passive_interface` | OSPF passive/silent interface | none | `ospf:1` |
| `ospf.authentication` | OSPF authentication | none | `ospf:1` |
| `ospf.redistribute` | OSPF redistribution/default route | none | `ospf:1` |
| `ospf.area_special` | OSPF stub/nssa/virtual-link | none | `ospf:1` |
| `bgp.process` | BGP process and router-id | `bgp:65000` | none |
| `bgp.neighbor` | Basic BGP neighbor AS mapping | `bgp:65000:neighbor:10.0.0.2` | `bgp:65000` |
| `bgp.network` | BGP network statement | none | `bgp:65000` |
| `bgp.password` | BGP neighbor authentication | none | `bgp:65000` |
| `bgp.policy` | BGP route-policy/route-map/filter binding | none | `bgp:65000`, optional `route-policy:*`, `route-filter:*` |
| `bgp.redistribute` | BGP redistribution/default route | none | `bgp:65000` |
| `bgp.attribute` | BGP attribute tuning | none | `bgp:65000` |
| `rip.process` | RIP process/version context | `rip:default` or `rip:*` | none |
| `rip.network` | RIP network statement | none | `rip:*` |
| `rip.redistribute` | RIP redistribution | none | `rip:*` |
| `isis.process` | IS-IS process context | `isis:1` or `isis:*` | none |
| `isis.network_entity` | IS-IS NET/network-entity | none | `isis:*` |
| `isis.interface_tuning` | IS-IS level/cost/auth tuning | none | `isis:*` |
| `isis.redistribute` | IS-IS redistribution | none | `isis:*` |
| `bfd.session` | BFD session and endpoint binding | `bfd:SESSION1` | `peer:*`, `source:*`, optional `interface:*` |
| `fhrp.vrrp` | VRRP/HSRP/FHRP virtual gateway behavior | `vrrp:Vlanif10:1` | `interface:Vlanif10` |
| `dhcp.pool` | DHCP pool scope/options | `dhcp-pool:LAN`, `subnet:*` | `gateway:*` |
| `pbr.policy` | Policy-based routing policy block | `pbr:PBR1` | ACL/nexthop dependencies later |
| `pbr.binding` | Interface PBR binding | none | `interface:*`, `route-policy:*` |
| `multicast` | Global multicast/PIM/IGMP controls | none | RP/interface dependencies later |
| `multicast.interface` | Interface PIM/IGMP controls | none | `interface:*` |
| `route_filter` | Prefix-list/ip-prefix/as-path/community filter | `route-filter:EXPORT` | none |
| `route_policy` | Route-policy/route-map block | `route-policy:EXPORT` | `acl:*`, `route-filter:*` |
| `qos.classifier` | QoS classifier | `qos-classifier:C1` | `acl:*` |
| `qos.behavior` | QoS behavior/action body | `qos-behavior:B1` | none |
| `qos.policy` | QoS policy joining classifier and behavior | `qos-policy:P1` | `qos-classifier:*`, `qos-behavior:*` |
| `qos.binding` | Interface QoS policy binding | none | `interface:*`, `qos-policy:*` |
| `management.ntp` | NTP server/source settings | none | none |
| `management.snmp` | SNMP community/host settings | none | none |
| `management.logging` | Loghost/info-center settings | none | none |
| `management.aaa` | AAA/radius/tacacs/local-user settings | none | none |
| `access.auth_profile` | NAC/authentication profile | `auth-profile:*` | optional `dot1x-profile:*`, `mac-access-profile:*`, `domain:*` |
| `access.dot1x` | 802.1X profile/global command | optional `dot1x-profile:*` | none |
| `access.mac_auth` | MAC authentication/MAB profile/global command | optional `mac-access-profile:*` | none |
| `access.portal` | Portal authentication server/profile | `portal:*` | none |
| `access.radius_binding` | RADIUS scheme/domain lan-access binding | `radius-scheme:*`, `domain:*` | optional `radius-scheme:*` |
| `access.interface_binding` | Interface NAC binding | none | `interface:*`, optional `auth-profile:*`, `domain:*` |
| `zone` | Firewall zone | `zone:trust` | interface bindings later |
| `address_object` | Firewall address object | `addr:WEB` | none |
| `service_object` | Firewall service object | `svc:HTTP` | none |
| `security_policy` | Firewall rule/policy | `policy:allow-web` | `zone:*`, `addr:*`, `svc:*`, optional `time-range:*`, `profile:*` |
| `firewall.nat` | NAT/source-nat/destination-nat policy | `nat-policy:*` | `zone:*`, `addr:*`, `svc:*` where detectable |
| `firewall.ipsec` | IKE/IPsec/VPN/crypto/tunnel-group block | `ike-peer:*`, `ipsec-policy:*`, `crypto-map:*` | `acl:*`, peer/proposal refs |
| `firewall.profile` | URL/AV/IPS/application/user profile | `profile:*` | profile binding dependencies later |
| `time_range` | Time range/schedule object | `time-range:*` | none |
| `unknown` | Vendor-specific or unsupported | none | none |

The taxonomy is intentionally extensible. A new feature must define its
`provides`, `consumes`, status policy, and user-facing manual-review reason
before it is allowed to affect deployable output.

## ACL Binding Ownership

Interface modules intentionally do not own ACL binding lines. For example:

```text
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
 traffic-filter inbound acl 3000
```

is decomposed into:

- `interface.svi`: owns `interface Vlanif10` and the IP address.
- `acl_binding`: owns `traffic-filter inbound acl 3000` and consumes both
  `interface:Vlanif10` and `acl:3000`.

During module translation, `acl_binding` is rendered with explicit interface
context. This prevents duplicate output such as two `ip access-group` lines and
keeps binding semantics separate from interface address/configuration semantics.

The same rule applies to FHRP. `vrrp vrid ...` / `standby ...` lines are split
out of `interface.svi` into `fhrp.vrrp`, because VIP, priority, preempt, and
track behavior often differ by platform. The SVI remains the interface/IP
provider; the FHRP module consumes the interface and stays manual-review until a
domain-specific validator can prove semantic equivalence.

## OSPF Risk Separation

OSPF is not treated as one flat block. A source block such as:

```text
ospf 1 router-id 10.0.0.1
 area 0.0.0.0
  network 10.0.10.0 0.0.0.255
 silent-interface Vlanif10
 area 0.0.0.0 authentication-mode md5
 import-route static
```

is decomposed into:

- `ospf.process`: process id and router-id.
- `ospf.area`: plain area declaration.
- `ospf.network`: network announcement.
- `ospf.passive_interface`: passive/silent interface behavior.
- `ospf.authentication`: manual review.
- `ospf.redistribute`: manual review.

This prevents high-risk authentication and redistribution commands from being
merged into otherwise safe OSPF process/network translation.

## BGP Risk Separation

BGP follows the same split. A source block such as:

```text
bgp 65000
 router-id 10.0.0.1
 peer 10.0.0.2 as-number 65001
 peer 10.0.0.2 password cipher SECRET_KEY
 peer 10.0.0.2 route-policy EXPORT export
 network 10.10.0.0 255.255.255.0
 import-route static
```

is decomposed into:

- `bgp.process`: process AS and router-id.
- `bgp.neighbor`: basic peer AS relationship.
- `bgp.network`: network announcement.
- `bgp.password`: manual review with secret value redacted.
- `bgp.policy`: manual review, with route-policy/route-map and direct
  prefix-list/ip-prefix/as-path/community filter references linked when present.
- `bgp.redistribute`: manual review.

Only the low-risk process/neighbor/network pieces may enter `deployable_config`.
Password, route-policy/filter, community, attribute tuning, and redistribution
stay in `manual_review_config` with source evidence.

## Route, VRF, Policy, QoS, and Management Separation

Routing and switching are broader than OSPF/BGP. The module graph now also
separates:

- `static_route`: basic destination/mask/next-hop route.
- `static_route.option`: static routes with `track`, `bfd`, `tag`,
  `description`, `preference`, or similar behavior-changing options. These
  require manual review.
- `vrf`: VRF/VPN instance provider. VRF-aware routes consume `vrf:<name>`.
- `route_filter`: prefix-list/ip-prefix/as-path/community filters. These are
  separate providers because route-policy and BGP may reference them directly.
- `route_policy`: route-policy/route-map blocks. These stay manual-review and
  link to referenced ACLs and route filters where possible.
- `qos.classifier`, `qos.behavior`, `qos.policy`: QoS parts are separated so
  policy joins can be audited instead of flattened.
- `qos.binding`: interface-level `traffic-policy` / `service-policy` bindings
  are detached from interface modules and linked to `qos-policy:*`.
- `management.ntp`, `management.snmp`, `management.logging`,
  `management.aaa`: management-plane features are split so sensitive SNMP/AAA
  values can be redacted and reviewed without hiding safe NTP/loghost context.
- `management.ssh`, `management.pki`, `management.ntp_auth`,
  `management.netconf`, `management.restconf`, `management.telemetry`, and
  `telemetry.flow`: higher-risk management/API/telemetry entry points are typed
  and produce semantic-near skeletons only. Secrets are redacted and RBAC,
  certificate, collector, and exposure semantics stay in review.
- `bfd.session`: BFD endpoint/session modules. They are manual-review because
  timers, discriminators, interface binding, and routing-protocol linkage are
  not equivalent across vendors by syntax alone.
- `fhrp.vrrp`: VRRP/HSRP/FHRP lines detached from SVI modules with an explicit
  `fhrp_uses_interface` coupling.
- `dhcp.pool`: DHCP pool scope/gateway/options. It provides pool/subnet
  resources but stays manual-review until excluded ranges, leases, options, and
  relay behavior are validated.
- `interface.tunnel`: Tunnel/GRE-like interface modules. They record tunnel
  source/destination and protocol tags, but stay manual-review because routing,
  MTU, keepalive, and encapsulation semantics are coupled.
- `platform.stack`, `overlay.vxlan`, `overlay.evpn`, `nqa`, `ip_sla`,
  `eigrp`, and `interface.tunnel6`: broad platform/overlay/probe/tunnel modules
  are typed and shown as semantic-near suggestions instead of generic
  manual-review blobs. They remain outside `deployable_config`.
- `ipv6.nd_snooping`, `ipv6.source_guard`, `ipv6.ra_guard`, `pbr.track`,
  `pbr.verify`, `ospf.te`, `multicast.msdp`, and `fhrp.track`: control-plane
  linkage modules now have explicit target-shaped suggestions and confirmation
  points instead of opaque review comments.
- `l2.ring_protection`, `l2.smart_link`, `l2.mlag`, `l2.gvrp`, `l2.mvrp`,
  `l2.device_tracking`, `l2.errdisable`, `monitor.rspan`, and `oam.cfm`:
  advanced switching/resilience/OAM modules now produce reviewable target
  skeletons with the original source module beside them in the UI.
- `bgp.vpnv4`, `bgp.evpn`, `bgp.flowspec`, `bgp.confederation`,
  `bgp.route_reflector`, `bgp.max_prefix`, `bgp.gtsm`, and
  `bgp.graceful_restart`: advanced BGP address-family and neighbor-control
  lines now produce target-shaped review skeletons while preserving the rule
  that they are not auto-deployable.
- `firewall.ssl_vpn`, `firewall.dos`, `firewall.dlp`, `firewall.waf`,
  `firewall.load_balance`, `firewall.proxy`, `firewall.decryption`, and
  `firewall.routing`: higher-level firewall service modules now expose
  semantic-near skeletons for review while avoiding unsafe deployable output.
- `rip.*` and `isis.*`: legacy/IGP routing protocols are typed instead of
  `unknown`, but remain manual-review until process, metric, authentication, and
  redistribution equivalence can be validated.
- `pbr.policy` and `pbr.binding`: PBR is split from interface modules so users can
  see exactly which interface consumes which policy. It stays manual-review.
- `multicast` and `multicast.interface`: PIM/IGMP lines are separated from
  ordinary interface configuration and kept manual-review.

This gives users line-level evidence for non-OSPF/BGP features instead of
burying them in `unknown` or one large `qos`/`system` bucket.

## Firewall Advanced Feature Separation

Firewall migration is especially risky because syntax that looks similar can
carry different session, NAT, security-profile, or VPN semantics. The module
graph therefore separates high-risk firewall features into typed manual-review
modules:

- `firewall.nat`: NAT/source-nat/destination-nat blocks. Zone/address/service
  references are linked where detectable, but the module never becomes
  automatically deployable.
- `firewall.ipsec`: IKE/IPsec/VPN/crypto/tunnel-group blocks. Sensitive key
  material in module source lines is redacted. ACL, peer, proposal, and transform
  references are recorded when the syntax exposes them.
- `firewall.profile`: URL filter, antivirus, IPS/intrusion, application, and user
  profiles. These depend on target-platform signature/profile databases and stay
  manual-review.
- `time_range`: schedule/time objects. They are typed so policies can eventually
  consume them, but they stay manual-review until calendar semantics are proven.
- `security_policy` now links detectable `time-range`/`schedule` and profile
  references to their provider modules, so the review view can show exactly
  which security rule depends on which schedule or inspection profile.
- `object_group` is separated from ACLs. ACL modules may consume both
  `object-group:*` and `time-range:*`, making advanced ACL review evidence
  explicit instead of hiding it in a generic ACL block.
- `object_group.member` splits each `network-object`, `service-object`, or
  `port-object` line from the parent container. The parent provides the object
  group name; each member consumes that parent and remains manual-review. This
  lets the review UI expand object groups without pretending their member syntax
  is automatically portable.

This prevents advanced firewall commands from being hidden inside `unknown` or a
generic `security_policy` block, while still honoring the rule that uncertain
equivalence must not enter `deployable_config`.

## Non-Goals

This layer does not claim semantic equivalence and does not replace the strong
IR path. It is a safer decomposition and evidence layer for:

- module-by-module translation,
- dependency-aware assembly,
- manual-review evidence,
- future UI visibility.

Anything that cannot be confidently translated must remain in `manual_review`.

## Next Steps

1. Normalize object-group member tags further for ASA/Hillstone/Topsec variants
   without overclaiming cross-vendor equivalence.
2. Split remaining interface-level routing features such as NAT-on-interface and
   advanced multicast/RP dependencies.
3. Replace fallback's remaining flat line-by-line paths gradually, one feature
   family at a time.
