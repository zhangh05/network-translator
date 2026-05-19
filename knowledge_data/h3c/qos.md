# H3C QoS Configuration

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
 filter <permit|deny>
```

Actions: remark, police, filter.

## QoS Policy

```
qos policy <name>
 classifier <class_name> behavior <behavior_name>
```

Bind classifier to behavior.

## Apply Policy

```
interface <interface>
 qos apply policy <policy_name> inbound
 qos apply policy <policy_name> outbound
```

## QoS Marking

```
remark dscp <ef|af|be>
remark 8021p <0-7>
remark local-precedence <0-7>
```

Mark packet fields.

## Rate Limiting

```
car cir <rate> pir <peak_rate>
qos lr inbound cir <rate> cbs <burst> pbs <peak_burst>
```

Interface rate limiting.

## Queue Scheduling

```
qos queue-profile <name>
 schedule pq <queue_list>
 schedule wrr <queue_list> weight <weight_list>
 schedule wfq <queue_list>
```

PQ, WRR, WFQ scheduling.

## H3C QoS Commands Reference

| Cisco | H3C |
|-------|-----|
| `class-map` | `traffic classifier` |
| `policy-map` | `qos policy` |
| `match` | `if-match` |
| `set dscp` | `remark dscp` |
| `set cos` | `remark 8021p` |
| `police cir` | `car cir` |
| `priority` | `schedule pq` |
| `fair-queue` | `schedule wf q` |
| `service-policy input` | `qos apply policy inbound` |
| `random-detect` | `qos queue-profile` |