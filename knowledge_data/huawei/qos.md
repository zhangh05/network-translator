# Huawei QoS Configuration

## Traffic Classifier

```
traffic classifier <name>
 if-match <condition>
```

Conditions: `acl <id>`, `vlan-id <vlan>`, `dscp <value>`, etc.

## Traffic Behavior

```
traffic behavior <name>
 remark dscp <value>
 car cir <rate> pir <peak>
```

Actions: remark, police, drop, redirect.

## Traffic Policy

```
traffic policy <name>
 classifier <class_name> behavior <behavior_name>
```

Bind classifier to behavior.

## Apply Policy

```
interface <interface>
 traffic-policy <policy_name> inbound
 traffic-policy <policy_name> outbound
```

## QoS Marking

```
remark dscp <ef|af|be>
remark 8021p <0-7>
remark local-precedence <0-7>
```

## Rate Limiting

```
car cir <committed-rate> pir <peak-rate>
qos lr inbound cir <rate> cbs <burst> pbs <peak-burst>
```

## Queue Scheduling

```
qos queue-profile <name>
 schedule pq <queue-list>
 schedule wrr <queue-list> weight <weight-list>
```

PQ (Priority Queue) and WRR (Weighted Round Robin).

## Huawei QoS Commands Reference

| Cisco | Huawei |
|-------|--------|
| `class-map` | `traffic classifier` |
| `policy-map` | `traffic policy` |
| `set dscp <val>` | `remark dscp <val>` |
| `set cos <val>` | `remark 8021p <val>` |
| `police cir <rate>` | `car cir <rate>` |
| `priority queue` | `schedule pq` |
| `fair-queue` | `schedule wrr` |
| `service-policy input` | `traffic-policy inbound` |