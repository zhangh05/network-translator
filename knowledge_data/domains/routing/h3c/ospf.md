# H3C OSPF Configuration (Routing Domain)
# H3C OSPF Configuration

## Basic OSPF
```
ospf <process-id> router-id <ip>
 area <area-id>
  network <prefix> <wildcard>
```

## Area Configuration
```
ospf 1 router-id 1.1.1.1
 area 0
  authentication-mode md5
 area 1
  stub
 area 2
  nssa
```

## Interface OSPF
```
interface GigabitEthernet0/0/1
 ospf cost <1-65535>
 ospf dr-priority <0-255>
 ospf network-type p2p|broadcast
 ospf authentication-mode md5 1 cipher <key>
```

## Redistribution
```
ospf 1
 import-route static cost <val>
 import-route direct cost <val>
 import-route bgp cost <val>
 default-route-advertise always
```

## Silent Interface
```
ospf 1
 silent-interface all
 undo silent-interface GigabitEthernet0/0/1
```

## OSPFv3
```
ospfv3 <process-id>
 router-id <ip>
interface GigabitEthernet0/0/1
 ospfv3 <process-id> area <area-id>
```
