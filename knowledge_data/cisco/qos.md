# Cisco QoS Configuration

## Class Map

```
class-map <match_any|match_all> <name>
 match access-group name <acl_name>
 match dscp <value>
 match cos <value>
 match vlan <vlan_id>
```

Define traffic classification.

## Policy Map

```
policy-map <name>
 class <class_name>
  set dscp <value>
  set cos <value>
  set precedence <value>
  police cir <rate> bc <burst>
  bandwidth <percent>
  priority <percent>
```

Define service policy actions.

## Service Policy Application

```
interface <interface>
 service-policy input <policy_name>
 service-policy output <policy_name>
```

Apply policy to interface.

## Congestion Management

```
priority queue <queue_id>
bandwidth <percent>
fair-queue
queue-limit <packets>
```

Queuing mechanisms.

## Congestion Avoidance

```
class-map
 random-detect dscp-based
 random-detect ecn
```

RED/WRED configuration.

## Marking

```
set dscp <ef|af|be>
set cos <0-7>
set precedence <0-7>
set qos-group <0-99>
```

Mark traffic fields.

## Policing

```
police cir <rate> pir <peak_rate> bc <burst> be <excess_burst>
police cir <rate> conform-action <action> exceed-action <action> violate-action <action>
```

Rate limiting with policing.

## Cisco QoS Commands Reference

| Cisco | Huawei |
|-------|--------|
| `class-map` | `traffic classifier` |
| `policy-map` | `traffic policy` |
| `match` | `if-match` |
| `set dscp` | `remark dscp` |
| `set cos` | `remark 8021p` |
| `police cir` | `car cir` |
| `priority` | `schedule pq` |
| `bandwidth` | `schedule wrr` |
| `service-policy input` | `traffic-policy inbound` |
| `random-detect` | `qos queue-profile` |