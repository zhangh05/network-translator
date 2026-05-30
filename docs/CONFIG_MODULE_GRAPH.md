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
- Routing modules such as OSPF
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
  `interface.svi`, `interface.physical`, `acl`, `acl_binding`, `ospf`,
  `zone`, `address_object`, `service_object`, `security_policy`, or `unknown`.
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
| `acl` | ACL definition | `acl:3000` | objects or time ranges later |
| `acl_binding` | ACL bind point | none | `acl:3000`, `interface:*` |
| `ospf` | OSPF process block | `ospf:1` | route policy/BFD later |
| `bgp` | BGP process block | `bgp:*` later | peer/policy/VRF later |
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

## Non-Goals

This layer does not claim semantic equivalence and does not replace the strong
IR path. It is a safer decomposition and evidence layer for:

- module-by-module translation,
- dependency-aware assembly,
- manual-review evidence,
- future UI visibility.

Anything that cannot be confidently translated must remain in `manual_review`.

## Next Steps

1. Split OSPF and BGP into submodules: process, area, peer, redistribution,
   authentication, and policy binding.
2. Move ACL binding translation from interface-body fallback into a dedicated
   module translator with explicit interface context.
3. Split firewall NAT/IPsec/profile features into typed manual-review modules.
4. Replace fallback's remaining flat line-by-line paths gradually, one feature
   family at a time.
