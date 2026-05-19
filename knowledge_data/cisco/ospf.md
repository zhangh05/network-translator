# Cisco OSPF Configuration

## Basic OSPF
```
router ospf <process-id>
 router-id <ip>
 network <prefix> <wildcard> area <area-id>
```

## Area Configuration
```
router ospf 1
 area 0 authentication message-digest
 area 1 stub
 area 2 nssa
 area 3 stub no-summary
```

## Interface OSPF
```
interface GigabitEthernet0/1
 ip ospf cost <1-65535>
 ip ospf priority <0-255>
 ip ospf network point-to-point|broadcast
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 <key>
```

## Redistribution
```
router ospf 1
 redistribute static subnets
 redistribute connected subnets
 redistribute bgp <asn> subnets metric <val>
 default-information originate always
```

## Passive Interface
```
router ospf 1
 passive-interface default
 no passive-interface GigabitEthernet0/1
```

## OSPFv3 (IPv6)
```
ipv6 router ospf <process-id>
 router-id <ip>
interface GigabitEthernet0/1
 ipv6 ospf <process-id> area <area-id>
```
