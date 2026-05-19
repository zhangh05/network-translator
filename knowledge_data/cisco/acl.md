# Cisco ACL Configuration

## Standard ACL
```
access-list <1-99> permit <source> <wildcard>
access-list <1-99> deny <source> <wildcard>
```
Applied: `ip access-group <acl_id> in|out`

## Extended ACL
```
access-list <100-199> permit tcp <src> <src_wc> <dst> <dst_wc> eq <port>
access-list <100-199> permit udp <src> <src_wc> <dst> <dst_wc> eq <port>
access-list <100-199> permit icmp <src> <src_wc> <dst> <dst_wc> [<type>]
access-list <100-199> deny ip <src> <src_wc> <dst> <dst_wc>
```

## Named ACL
```
ip access-list extended <name>
 permit tcp any host <ip> eq <port>
 deny ip any any
```

## Interface ACL
```
interface <iface>
 ip access-group <acl_id> in|out
```

## VLAN ACL (VACL)
```
vlan access-map <name> <seq>
 match ip address <acl>
 action forward|drop
vlan filter <name> vlan-list <vlans>
```

## Time-based ACL
```
time-range <name>
 periodic <day> <start> to <end>
ip access-list extended <name>
 permit <...> time-range <name>
```

## Logging
```
access-list <id> deny ip any any log
```
