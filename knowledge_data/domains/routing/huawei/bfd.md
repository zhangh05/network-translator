# Huawei BFD Configuration (Routing Domain)

## Global BFD
```
bfd
 quit
```

## BFD Session
```
bfd <name> bind peer-ip <ip>
 discriminator local <id>
 discriminator remote <id>
 min-tx-interval <ms>
 min-rx-interval <ms>
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
ip route-static <prefix> <mask> <next-hop> track bfd-session <name>
```
