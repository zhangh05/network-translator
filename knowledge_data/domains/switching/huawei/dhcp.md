# Huawei DHCP Snooping (Switching Domain)

## Enable DHCP Snooping Globally
```
dhcp snooping enable
```

## Enable DHCP Snooping per VLAN
```
vlan <id>
 dhcp snooping enable
```

## Trust Uplink Ports
DHCP snooping requires trusted ports on uplink interfaces that connect
to DHCP servers or upstream switches:
```
interface GigabitEthernet0/0/X
 dhcp snooping trust
```

## Traffic Filter with ACL
```
acl number <3000-3999>
 rule <seq> <action> <protocol> <src> <dst>
interface Vlanif<id>
 traffic-filter inbound acl <number>
```
