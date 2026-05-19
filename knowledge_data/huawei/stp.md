# Huawei STP Configuration

## Enable STP

```
stp enable
stp mode <rstp|stp|pvst>
```

- `stp enable` — enable STP globally (default on Huawei)
- `stp mode rstp` — use Rapid Spanning Tree (default)

## Bridge Priority

```
stp priority <priority>
stp port priority <priority>
```

- `stp priority <0-61440>` — set bridge priority (lower wins)
- `stp port priority` — set port priority

## Port Cost

```
interface <interface>
 stp cost <cost>
```

Set path cost for port (lower cost = preferred).

## Edge Port

```
interface <interface>
 stp edged-port enable
```

Configure port as Edge Port (like Cisco `spanning-tree portfast`).

## Root Guard / BPDU Guard

```
interface <interface>
 stp bpdu-filter enable
 stp root-protect
 stp tc-protect
```

- `stp root-protect` — Root Guard equivalent
- `stp bpdu-filter` — BPDU Filter

## TC Protection

```
stp tc-protection
stp tc-protection interval <seconds>
stp tc-protection threshold <count>
```

Protect against TC (Topology Change) attacks.

## Huawei STP Commands Reference

| Cisco | Huawei |
|-------|--------|
| `spanning-tree mode pvst` | `stp mode rstp` |
| `spanning-tree vlan <id> priority <pri>` | `stp priority <pri>` |
| `spanning-tree cost <cost>` | `stp cost <cost>` |
| `spanning-tree portfast` | `stp edged-port enable` |
| `spanning-tree bpduguard` | `stp bpdu-filter enable` |
| `spanning-tree guard root` | `stp root-protect` |
| `spanning-tree uplinkfast` | `stp enable` + load balancing |