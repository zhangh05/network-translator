# Cisco Security Zone Configuration (Firewall Domain)

## Zone-Based Policy Firewall

```
zone security <zone_name>
```

Create security zone.

## Zone Pairs

```
zone-pair security <source> <destination>
```

Define zone pair for traffic flow.

## Class Map (Inspect)

```
class-map type inspect <name>
 match protocol <protocol>
 match access-group name <acl_name>
```

Inspect traffic classification.

## Policy Map (Inspect)

```
policy-map type inspect <name>
 class type inspect <class_name>
  inspect
  drop
  pass
```

Define inspection actions.

## Apply Policy to Zone Pair

```
zone-pair security <source> destination <destination>
 service-policy type inspect <policy_name>
```

Apply policy.

## Default Zone Behavior

```
zone-pair security source <zone> destination <zone>
 drop
```

Default deny.

## Self Zone

```
zone security local
```

Local zone for device-originated traffic.

## Cisco Security Zone Commands Reference

| Cisco | Huawei |
|-------|--------|
| `zone security <name>` | `firewall zone <name>` |
| `zone-pair security` | `zone-pair security` |
| `class-map type inspect` | `packet-filter` or ACL |
| `policy-map type inspect` | `service-policy` |
| `inspect` action | `permit` |
| `drop` action | `deny` |
| `pass` action | `permit` (stateless) |
| `zone-pair service-policy` | `zone-pair security` |