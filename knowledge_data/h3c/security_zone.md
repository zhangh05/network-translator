# H3C Security Zone Configuration

## Create Security Zone

```
zone security <zone_name>
```

Create security zone.

## Add Interfaces to Zone

```
zone security <zone_name>
 import interface <interface>
```

Assign interfaces.

## Zone Pair Policy

```
zone-pair security source <src_zone> destination <dst_zone>
 packet-filter <acl_id>
```

Inter-zone traffic policy.

## Default Deny

```
zone-pair security source <src> destination <dst>
 deny
```

Default behavior is deny.

## Zone-based Firewall

```
zone-pair security source <src> destination <dst>
 qos <qos_policy>
```

Apply QoS to zone-pair.

## Local Zone

```
zone security local
 import interface <interface>
```

Device-originated traffic zone.

## Display Zone

```
display zone
display zone-pair
```

## H3C Security Zone Commands Reference

| Cisco | H3C |
|-------|-----|
| `zone security <name>` | `zone security <name>` |
| `zone-pair security` | `zone-pair security` |
| `class-map type inspect` | `packet-filter` |
| `policy-map type inspect` | `qos` |
| `inspect` | `permit` |
| `drop` | `deny` |
| `pass` | `permit` (stateless) |
| `zone-pair service-policy` | `zone-pair qos` |