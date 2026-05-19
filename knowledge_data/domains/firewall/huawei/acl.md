# Huawei ACL Configuration (Firewall Domain)

## Basic ACL (2000-2999)
```
acl number 2000
 rule <5|10|15...> permit source <src> <wildcard>
 rule <seq> deny source <src> <wildcard>
```

## Advanced ACL (3000-3999)
```
acl number 3000
 rule <seq> permit tcp source <src> <wc> destination <dst> <wc> destination-port eq <port>
 rule <seq> permit udp source <src> <wc> destination <dst> <wc> destination-port eq <port>
 rule <seq> permit icmp source <src> <wc> destination <dst> <wc> [icmp-type <type>]
 rule <seq> deny ip source <src> <wc> destination <dst> <wc>
```

## Named ACL
```
acl name <acl_name> <2000-3999>
 rule <seq> permit ip source <src> <wc> destination <dst> <wc>
```

## Interface ACL Application
```
interface <iface>
 traffic-filter inbound acl <number|name>
 traffic-filter outbound acl <number|name>
```

## Time-based ACL
```
time-range <name> <start> to <end> <daily|weekdays|weekends>
acl number 3000
 rule <seq> permit ip source <src> <wc> destination <dst> <wc> time-range <name>
```

## Logging
```
acl number 3000
 rule <seq> deny ip source any destination any logging
```
