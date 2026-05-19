# H3C BFD Configuration (Routing Domain)

## Global BFD
```
bfd multi-hop min-transmit-interval <ms> min-receive-interval <ms> detect-multiplier <num>
```

## BFD Session
```
bfd <name> peer-ip <ip>
 discriminator local <id>
 discriminator remote <id>
 min-transmit-interval <ms>
 min-receive-interval <ms>
 detect-multiplier <num>
 commit
```

## BFD with OSPF
```
ospf <pid>
 bfd all-interfaces enable
```

## BFD with BGP
```
bgp <asn>
 peer <ip> bfd enable
```

## BFD with Static Route
```
ip route-static <prefix> <mask> <next-hop> bfd enable
```
