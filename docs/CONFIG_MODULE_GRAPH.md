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
  `static_route`, `vrf`, `route_policy`, `qos.policy`, `management.ntp`,
  `ospf.process`, `bgp.process`, `bfd.session`, `fhrp.vrrp`, `dhcp.pool`,
  `interface.tunnel`, `zone`, `address_object`, `service_object`,
  `security_policy`, or `unknown`.
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
| `acl` | ACL definition | `acl:3000` | objects or time ranges later |
| `acl_binding` | ACL bind point | none | `acl:3000`, `interface:*` |
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
| `bgp.policy` | BGP route-policy/route-map/filter binding | none | `bgp:65000` |
| `bgp.redistribute` | BGP redistribution/default route | none | `bgp:65000` |
| `bgp.attribute` | BGP attribute tuning | none | `bgp:65000` |
| `bfd.session` | BFD session and endpoint binding | `bfd:SESSION1` | `peer:*`, `source:*`, optional `interface:*` |
| `fhrp.vrrp` | VRRP/HSRP/FHRP virtual gateway behavior | `vrrp:Vlanif10:1` | `interface:Vlanif10` |
| `dhcp.pool` | DHCP pool scope/options | `dhcp-pool:LAN`, `subnet:*` | `gateway:*` |
| `route_policy` | Route-policy/route-map block | `route-policy:EXPORT` | `acl:*` |
| `qos.classifier` | QoS classifier | `qos-classifier:C1` | `acl:*` |
| `qos.behavior` | QoS behavior/action body | `qos-behavior:B1` | none |
| `qos.policy` | QoS policy joining classifier and behavior | `qos-policy:P1` | `qos-classifier:*`, `qos-behavior:*` |
| `management.ntp` | NTP server/source settings | none | none |
| `management.snmp` | SNMP community/host settings | none | none |
| `management.logging` | Loghost/info-center settings | none | none |
| `management.aaa` | AAA/radius/tacacs/local-user settings | none | none |
| `zone` | Firewall zone | `zone:trust` | interface bindings later |
| `address_object` | Firewall address object | `addr:WEB` | none |
| `service_object` | Firewall service object | `svc:HTTP` | none |
| `security_policy` | Firewall rule/policy | `policy:allow-web` | `zone:*`, `addr:*`, `svc:*` |
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
- `bgp.policy`: manual review.
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
- `route_policy`: route-policy/route-map blocks. These stay manual-review and
  link to referenced ACLs where possible.
- `qos.classifier`, `qos.behavior`, `qos.policy`: QoS parts are separated so
  policy joins can be audited instead of flattened.
- `management.ntp`, `management.snmp`, `management.logging`,
  `management.aaa`: management-plane features are split so sensitive SNMP/AAA
  values can be redacted and reviewed without hiding safe NTP/loghost context.
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

This gives users line-level evidence for non-OSPF/BGP features instead of
burying them in `unknown` or one large `qos`/`system` bucket.

## Non-Goals

This layer does not claim semantic equivalence and does not replace the strong
IR path. It is a safer decomposition and evidence layer for:

- module-by-module translation,
- dependency-aware assembly,
- manual-review evidence,
- future UI visibility.

Anything that cannot be confidently translated must remain in `manual_review`.

## Next Steps

1. Split BGP address-family and VRF-aware peer context into submodules.
2. Split firewall NAT/IPsec/profile features into typed manual-review modules.
3. Split interface-level routing features such as PBR, NAT-on-interface, and
   multicast controls.
4. Replace fallback's remaining flat line-by-line paths gradually, one feature
   family at a time.
