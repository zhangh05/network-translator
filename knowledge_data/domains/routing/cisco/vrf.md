# Cisco VRF Configuration (Routing Domain)

## VRF Definition
```
ip vrf <name>
 rd <rd-value>
 route-target export <rt-value>
 route-target import <rt-value>
```

## VRF-lite (no MPLS)
```
ip vrf <name>
 rd <rd-value>
```

## Assign VRF to Interface
```
interface <interface>
 ip vrf forwarding <name>
 ip address <ip> <mask>
```

## VRF Static Route
```
ip route vrf <name> <prefix> <mask> <next-hop>
```
