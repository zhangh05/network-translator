# Huawei Security Zone Configuration

## Create Security Zone

```
firewall zone <name>
```

Create a security zone.

## Add Interfaces to Zone

```
firewall zone <name>
 add interface <interface>
 add interface <interface>
```

Assign interfaces to zone.

## Zone-pair Policy

```
zone-pair security source <src_zone> destination <dst_zone>
 packet-filter <acl_id> | permit
```

Configure inter-zone traffic policy.

## Default Zone Behavior

```
firewall default deny
```

Default deny all inter-zone traffic.

## Zone-based Firewall

```
zone-pair security source <src> destination <dst>
 service-policy https
```

Apply service policy to zone-pair.

## Display Zones

```
display zone
display zone-pair
```

## Trust Zone (Local)

```
firewall zone trust
 add interface <interface>
```

Pre-defined trust zone.

## Huawei Security Zone Commands Reference

| Cisco | Huawei |
|-------|--------|
| `zone-based policy` | `zone-pair security` |
| `zone-pair security source Trust dest Self` | `zone-pair security source trust destination local` |
| `class-map type inspect` | `zone-pair security` with `packet-filter` |
| `policy-map type inspect` | `service-policy` |
| `service-policy <name> interface` | `zone-pair security` |