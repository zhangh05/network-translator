# H3C QoS Configuration (Switching Domain)

## Traffic Classifier
```
traffic classifier <name> operator {and | or}
 if-match dscp <value>
 if-match ip-precedence <value>
 if-match acl <acl>
 if-match protocol <protocol>
```

## Traffic Behavior
```
traffic behavior <name>
 remark dscp <value>
 remark ip-precedence <value>
 car cir <rate> pir <rate> cbs <burst> pbs <burst>
 queue ef <bandwidth>
 queue af <bandwidth>
 queue wfq <weight>
 shaping <rate>
```

## Traffic Policy
```
traffic policy <name>
 classifier <classifier> behavior <behavior>
```

## Apply
```
interface <interface>
 traffic-policy <policy> inbound
 traffic-policy <policy> outbound
```
