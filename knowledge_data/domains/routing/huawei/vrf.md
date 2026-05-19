# Huawei VRF Configuration (Routing Domain)

## VRF Definition
```
ip vpn-instance <name>
 ipv4-family
  route-distinguisher <rd-value>
  vpn-target <rt-value> export-extcommunity
  vpn-target <rt-value> import-extcommunity
```

## Assign VRF to Interface
```
interface <interface>
 ip binding vpn-instance <name>
 ip address <ip> <mask>
```

## VRF Static Route
```
ip route-static vpn-instance <name> <prefix> <mask> <next-hop>
```
