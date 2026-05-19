# Cisco Interface Configuration (Firewall Domain)

## Naming Convention
- GigabitEthernet: `GigabitEthernet<slot>/<port>`
- TenGigabitEthernet: `TenGigabitEthernet<slot>/<port>`
- Loopback: `Loopback<0-2147483647>`
- VLAN Interface: `interface Vlan<id>`
- Port-channel: `interface Port-channel<id>`

## L3 Interface
```
interface GigabitEthernet0/1
 ip address <ip> <mask>
 ip address <ip> <mask> secondary
 no shutdown
 description <text>
```

## L2 Access
```
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan <id>
 spanning-tree portfast
```

## L2 Trunk
```
interface GigabitEthernet0/1
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan <list>
 switchport trunk native vlan <id>
```

## Sub-interface (Router-on-a-Stick)
```
interface GigabitEthernet0/1.100
 encapsulation dot1Q <vlan_id>
 ip address <ip> <mask>
```

## Port-channel
```
interface Port-channel1
 switchport mode trunk
interface GigabitEthernet0/1
 channel-group 1 mode active
```
