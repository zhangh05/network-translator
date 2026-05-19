# Cisco BGP Configuration

## Basic BGP
```
router bgp <asn>
 bgp router-id <ip>
 neighbor <ip> remote-as <asn>
```

## IPv4 Address Family
```
router bgp <asn>
 address-family ipv4 unicast
  neighbor <ip> activate
  network <prefix> mask <mask>
  redistribute connected
  redistribute static
```

## eBGP/iBGP
```
! eBGP (different AS)
router bgp 65001
 neighbor 10.0.0.2 remote-as 65002

! iBGP (same AS)
router bgp 65001
 neighbor 10.0.0.1 remote-as 65001
 neighbor 10.0.0.1 update-source Loopback0
```

## Route Reflector
```
router bgp <asn>
 neighbor <ip> route-reflector-client
```

## Peer Group
```
router bgp <asn>
 neighbor <name> peer-group
 neighbor <name> remote-as <asn>
 neighbor <ip> peer-group <name>
```

## BGP Authentication
```
router bgp <asn>
 neighbor <ip> password <key>
```

## Route Policy
```
route-map <name> permit <seq>
 match ip address <acl>
 set local-preference <val>
router bgp <asn>
 neighbor <ip> route-map <name> in|out
```
