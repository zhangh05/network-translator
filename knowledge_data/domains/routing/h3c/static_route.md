# H3C Static Route Configuration (Routing Domain)

## IPv4 Static Route
```
ip route-static <ip> <mask> <next-hop>
ip route-static <ip> <mask> <interface>
ip route-static <ip> <mask> <next-hop> preference <val>
```

## Default Route
```
ip route-static 0.0.0.0 0.0.0.0 <next-hop>
ip route-static 0.0.0.0 0.0.0.0 <interface>
```

## Floating Static Route
```
ip route-static <ip> <mask> <next-hop> preference 200
```

## IPv6 Static Route
```
ipv6 route-static <prefix> <len> <next-hop>
ipv6 route-static :: 0 <next-hop>
```

## VPN Instance Static Route
```
ip route-static vpn-instance <name> <ip> <mask> <next-hop>
```
