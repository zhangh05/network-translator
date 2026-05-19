# Huawei Interface Configuration (Switching Domain)

## Naming Convention
- GigabitEthernet: `GigabitEthernet<slot>/<subslot>/<port>` or `XGigabitEthernet<slot>/<subslot>/<port>`
- Loopback: `LoopBack<0-1023>`
- VLAN Interface: `interface Vlanif<id>`
- Eth-Trunk: `interface Eth-Trunk<id>`

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
 port default vlan <id>
 stp edged-port enable
```

## L2 Trunk
```
interface GigabitEthernet0/0/1
 port link-type trunk
 port trunk allow-pass vlan <list>
 port trunk pvid vlan <id>
```

## Sub-interface
```
interface GigabitEthernet0/0/1.100
 dot1q termination vid <vlan_id>
 ip address <ip> <mask>
```

## Eth-Trunk
```
interface Eth-Trunk1
 port link-type trunk
 port trunk allow-pass vlan <list>
interface GigabitEthernet0/0/1
 eth-trunk 1
```
