# Config Module Graph

This document records the module-decomposition layer introduced after the Beta
fallback hardening work.

## Goal

Large network configs should not be treated as one flat string. Before
translation, the source config can be decomposed into auditable modules:

- VLAN modules
- Interface modules
- ACL modules
- Routing modules such as OSPF
- Manual-review modules for unsupported or vendor-specific features

Each module keeps the original source lines and line span. It can provide named
resources, consume named resources, and depend on other modules.

## Current Scope

The first implementation is intentionally additive:

- `core/module_graph/` builds a graph from existing feature blocks.
- `FallbackNode` stores the graph under `_fallback_metadata["module_graph"]`.
- `ParseNode` builds the graph for both LLM and fallback paths.
- API results expose `module_summary` and `module_graph`.
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
- `feature`: normalized feature type, for example `vlan`, `interface`, `acl`,
  `ospf`, or `unknown`.
- `start_line` / `end_line`: original config line span.
- `source_lines`: original source config lines.
- `provides`: resources defined by the module, such as `vlan:10` or `acl:3000`.
- `consumes`: resources referenced by the module, such as `vlan:10` from an SVI
  or `acl:3000` from an interface ACL binding.
- `depends_on`: module ids that should be considered before this module.
- `tags`: lightweight hints such as `svi` or `trunk`.
- `status`: `translatable` or `manual_review`.
- `manual_review_reason`: user-facing reason when status is `manual_review`.

`ModuleDependency`:

- `from_module`: consumer module id.
- `to_module`: provider module id.
- `label`: resource key connecting the two modules.

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
- SVI module consumes `vlan:10` and `acl:3000`.
- Edges connect SVI -> VLAN and SVI -> ACL.

The source assembly view can render providers before the consumer:

```text
### module 0003:vlan:7 | feature=vlan | status=translatable | lines=7-7 | provides=vlan:10
vlan batch 10

### module 0002:acl:4 | feature=acl | status=translatable | lines=4-5 | provides=acl:3000
acl number 3000
 rule 5 permit ip

### module 0001:interface:1 | feature=interface | status=translatable | lines=1-3 | depends_on=0002:acl:4,0003:vlan:7 | provides=interface:Vlanif10 | consumes=acl:3000,vlan:10 | tags=svi
interface Vlanif10
 ip address 10.0.10.1 255.255.255.0
 traffic-filter inbound acl 3000
```

## Non-Goals

This layer does not claim semantic equivalence and does not replace the strong
IR path. It is a safer decomposition and evidence layer for:

- module-by-module translation,
- dependency-aware assembly,
- manual-review evidence,
- future UI visibility.

Anything that cannot be confidently translated must remain in `manual_review`.

## Next Steps

1. Add module translators that accept a single `ConfigModule` and return a
   typed module translation result.
2. Add an assembly policy that merges translated modules by dependency order
   while preserving safe source order.
3. Replace fallback's flat line-by-line path gradually, one feature family at a
   time, starting with VLAN + interface + ACL binding.
