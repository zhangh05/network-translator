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

## Non-Goals

This layer does not claim semantic equivalence and does not replace the strong
IR path. It is a safer decomposition and evidence layer for:

- module-by-module translation,
- dependency-aware assembly,
- manual-review evidence,
- future UI visibility.

Anything that cannot be confidently translated must remain in `manual_review`.
