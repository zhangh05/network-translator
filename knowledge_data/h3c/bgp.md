# H3C BGP Configuration

## Basic BGP
```
bgp <asn>
 router-id <ip>
 peer <ip> as-number <asn>
```

## IPv4 Address Family
```
bgp <asn>
 address-family ipv4 unicast
  peer <ip> enable
  network <prefix> <mask>
  import-route direct
  import-route static
```

## eBGP/iBGP
```
! eBGP
bgp 65001
 peer 10.0.0.2 as-number 65002

! iBGP
bgp 65001
 peer 10.0.0.1 as-number 65001
 peer 10.0.0.1 connect-interface LoopBack0
```

## Route Reflector
```
bgp <asn>
 address-family ipv4 unicast
  peer <ip> reflect-client
```

## Peer Group
```
bgp <asn>
 group <name> external|internal
 peer <name> as-number <asn>
 peer <ip> group <name>
```

## BGP Authentication
```
bgp <asn>
 peer <ip> password cipher <key>
```

## Route Policy
```
route-policy <name> permit node <seq>
 if-match acl <number>
 apply local-preference <val>
bgp <asn>
 peer <ip> route-policy <name> import|export
```
