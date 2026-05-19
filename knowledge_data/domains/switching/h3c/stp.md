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