# H3C Interface Configuration (Switching Domain)

## Naming Convention
- GigabitEthernet: `GigabitEthernet<slot>/<subslot>/<port>`
- Loopback: `LoopBack<0-1023>`
- VLAN Interface: `interface Vlan-interface<id>` (v5) or `interface Vlanif<id>` (v7)
- Bridge-Aggregation: `interface Bridge-Aggregation<id>`

## L3 Interface
```
interface GigabitEthernet0/0/1
 ip address <ip> <mask>
 ip address <ip> <mask> sub
 undo shutdown
 description <text>
```

## L2 Access
```
interface GigabitEthernet0/0/1
 port link-type access
 port access vlan <id>
 stp edged-port enable
```

## L2 Trunk
```
interface GigabitEthernet0/0/1
 port link-type trunk
 port trunk permit vlan <list>
 port trunk pvid vlan <id>
```

## Sub-interface
```
interface GigabitEthernet0/0/1.100
 vlan-type dot1q vid <vlan_id>
 ip address <ip> <mask>
```

## Bridge-Aggregation
```
interface Bridge-Aggregation1
 port link-type trunk
 port trunk permit vlan <list>
interface GigabitEthernet0/0/1
 port link-aggregation group 1
```
