# Cisco QoS Configuration (Routing Domain)

## Class-Map
```
class-map match-any <name>
 match ip dscp <value>
 match ip precedence <value>
 match access-group <acl>
 match protocol <protocol>
```

## Policy-Map
```
policy-map <name>
 class <class-name>
  set ip dscp <value>
  set ip precedence <value>
  police <rate> <burst> conform-action transmit exceed-action drop
  bandwidth <kbps>
  priority <kbps>
  shape average <rate>
  queue-limit <packets>
 class class-default
  fair-queue
```

## Service Policy
```
interface <interface>
 service-policy input <policy-name>
 service-policy output <policy-name>
```

## NBAR
```
ip nbar protocol-discovery
interface <interface>
 ip nbar protocol-discovery
```
