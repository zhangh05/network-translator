# Cisco BFD Configuration (Routing Domain)

## BFD Parameters
```
bfd interval <ms> min_rx <ms> multiplier <num>
```

## BFD with OSPF
```
router ospf <pid>
 bfd all-interfaces
```

## BFD with BGP
```
router bgp <asn>
 bfd all-interfaces
 neighbor <ip> fall-over bfd
```

## BFD with Static Route
```
ip route <prefix> <mask> <next-hop> bfd
ip route <prefix> <mask> <next-hop> bfd <source>
```
