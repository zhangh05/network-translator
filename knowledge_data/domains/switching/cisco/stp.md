# Cisco STP Configuration (Switching Domain)

## Enable STP

```
spanning-tree mode <pvst|rapid-pvst|mst>
spanning-tree vlan <vlan_id> priority <priority>
```

- `spanning-tree mode pvst` — Per-VLAN Spanning Tree
- `rapid-pvst` — Rapid PVST (RSTP per VLAN)

## PortFast

```
interface <interface>
 spanning-tree portfast
 spanning-tree portfast trunk
 spanning-tree bpduguard enable
```

- `portfast` — skip listening/learning on access ports
- `bpduguard` — disable port on BPDU receipt

## UplinkFast / BackboneFast

```
spanning-tree uplinkfast
spanning-tree backbonefast
```

Legacy convergence enhancements.

## Root Guard

```
interface <interface>
 spanning-tree guard root
```

Prevent foreign root bridge on port.

## Loop Guard

```
spanning-tree loopguard default
interface <interface>
 spanning-tree guard loop
```

Detect unidirectional link failures.

## Port Cost

```
interface <interface>
 spanning-tree cost <cost>
 spanning-tree vlan <vlan_id> port-priority <priority>
```

Lower cost = preferred path.

## MSTP

```
spanning-tree mode mst
spanning-tree mst configuration
 instance <id> vlan <vlan_list>
 name <region_name>
 revision <num>
```

Multiple Spanning Tree Protocol.

## Cisco STP Commands Reference

| Cisco | Huawei |
|-------|--------|
| `spanning-tree mode pvst` | `stp mode rstp` (or `stp mode stp`) |
| `spanning-tree vlan <id> priority <pri>` | `stp priority <pri>` |
| `spanning-tree cost <cost>` | `stp cost <cost>` |
| `spanning-tree portfast` | `stp edged-port enable` |
| `spanning-tree bpduguard` | `stp bpdu-filter enable` |
| `spanning-tree guard root` | `stp root-protect` |
| `spanning-tree uplinkfast` | `stp enable` + load balancing |
| `spanning-tree mode mst` | `stp mode mstp` |