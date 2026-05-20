# H3C STP Configuration (Switching Domain)

## Enable STP

```
stp enable
stp mode <rstp|mstp|pvst>
```

- `stp enable` — enable globally (default on H3C)
- `stp mode rstp` — Rapid Spanning Tree

## Bridge Priority

```
stp priority <priority>
stp port priority <priority>
```

- `stp priority <0-61440>` — set bridge priority
- `port priority` — port-level priority

## Port Cost

```
interface <interface>
 stp cost <cost>
```

Lower cost = preferred path.

## Edge Port

```
interface <interface>
 stp edged-port
```

Like Cisco `spanning-tree portfast`.

## Root Guard / BPDU Guard

```
interface <interface>
 stp bpdu-protection
 stp root-protection
```

- `bpdu-protection` — BPDU Guard
- `root-protection` — Root Guard

## TC Protection

```
stp tc-protection
stp tc-protection threshold <count>
```

Protect against Topology Change attacks.

## MSTP Region

```
stp region-configuration
 region-name <name>
 instance <id> vlan <vlan_list>
 active region-configuration
```

Multiple Spanning Tree regions.

## MSTP Root Role (Cisco root primary / root secondary)

Cisco MST root role commands and their H3C equivalents:

| Cisco | H3C | Notes |
|-------|-----|-------|
| `spanning-tree mst <id> root primary` | `stp instance <id> root primary` | Equivalent semantics; H3C may require priority 24576 |
| `spanning-tree mst <id> root secondary` | `stp instance <id> root secondary` | Equivalent semantics; H3C may require priority 28672 |
| `spanning-tree mst <id> priority <pri>` | `stp instance <id> priority <pri>` | Direct priority mapping |

- **Do not** silently omit root role semantics when translating.
- If the source has `root primary` or `root secondary`, the output **must** contain the equivalent role.
- If the instance-to-instance mapping cannot be determined, output `{cp} MANUAL_REVIEW`.
- Root role can be expressed as `stp instance <id> root primary` or via explicit priority (24576 for primary, 28672 for secondary).

## H3C STP Commands Reference

| Cisco | H3C |
|-------|-----|
| `spanning-tree mode pvst` | `stp mode rstp` / `stp mode mstp` |
| `spanning-tree vlan <id> priority <pri>` | `stp priority <pri>` |
| `spanning-tree cost <cost>` | `stp cost <cost>` |
| `spanning-tree portfast` | `stp edged-port` |
| `spanning-tree bpduguard` | `stp bpdu-protection` |
| `spanning-tree guard root` | `stp root-protection` |
| `spanning-tree mode mst` | `stp mode mstp` + `stp region-configuration` |
| `spanning-tree mst <id> root primary` | `stp instance <id> root primary` or `stp instance <id> priority 24576` |
| `spanning-tree mst <id> root secondary` | `stp instance <id> root secondary` or `stp instance <id> priority 28672` |