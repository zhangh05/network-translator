# H3C ACL Configuration (Firewall Domain)

## Basic ACL (2000-2999)
```
acl basic 2000
 rule <5|10|15...> permit source <src> <wildcard>
 rule <seq> deny source <src> <wildcard>
```

## Advanced ACL (3000-3999)
```
acl advanced 3000
 rule <seq> permit tcp source <src> <wc> destination <dst> <wc> destination-port eq <port>
 rule <seq> permit udp source <src> <wc> destination <dst> <wc> destination-port eq <port>
 rule <seq> permit icmp source <src> <wc> destination <dst> <wc> [icmp-type <type>]
 rule <seq> deny ip source <src> <wc> destination <dst> <wc>
```

## Named ACL
```
acl name <acl_name>
 rule <seq> permit ip source <src> <wc> destination <dst> <wc>
```

## Interface ACL Application
```
interface <iface>
 packet-filter <number|name> inbound
 packet-filter <number|name> outbound
```

## Time-based ACL
```
time-range <name> <start> to <end> <daily|weekly>
acl advanced 3000
 rule <seq> permit ip source <src> <wc> destination <dst> <wc> time-range <name>
```

## Logging
```
acl advanced 3000
 rule <seq> deny ip source any destination any logging
```
