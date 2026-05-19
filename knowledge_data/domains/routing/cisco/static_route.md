# Cisco Static Route Configuration (Routing Domain)

## IPv4 Static Route
```
ip route <network> <mask> <next-hop>
ip route <network> <mask> <interface>
ip route <network> <mask> <next-hop> <distance>
```

## Default Route
```
ip route 0.0.0.0 0.0.0.0 <next-hop>
ip route 0.0.0.0 0.0.0.0 <interface>
```

## Floating Static Route
```
ip route <network> <mask> <next-hop> 200
```

## IPv6 Static Route
```
ipv6 route <prefix>/<len> <next-hop>
ipv6 route ::/0 <next-hop>
```

## VRF Static Route
```
ip route vrf <vrf_name> <network> <mask> <next-hop>
```
