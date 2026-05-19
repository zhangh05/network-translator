# Cisco SNMP Configuration (Routing Domain)

## SNMPv2c
```
! Read-only community
snmp-server community <string> ro
! Read-write community
snmp-server community <string> rw
! ACL restriction
snmp-server community <string> ro <acl-name>
! Trap destination
snmp-server enable traps
snmp-server host <ip> version 2c <community>
snmp-server location <text>
snmp-server contact <text>
```

## SNMPv3
```
snmp-server group <group> v3 priv read <view> write <view>
snmp-server user <user> <group> v3 auth sha <key> priv aes 256 <key>
! Trap with SNMPv3
snmp-server enable traps
snmp-server host <ip> version 3 priv <user>
```
