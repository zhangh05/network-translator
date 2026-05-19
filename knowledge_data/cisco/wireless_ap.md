# Cisco Wireless AP Configuration

## Register AP

```
ap <name>
 model <model_number>
 ip address <ip> <mask> <gateway>
```

Manual AP provisioning.

## AP Name and Location

```
ap <name>
 location <location_string>
 ap-type <ap_type>
```

Set location metadata.

## AP Join Configuration

```
ap auth-type <mac-auth|sn-auth|auth-handshake>
 username <user> password <pwd>
```

AP authentication mode.

## AP Time Configuration

```
ap group <group_name>
```

AP group membership.

## AP Radio Configuration

```
ap <name>
 dot11 5ghz radio
  power <power_level>
  channel <channel> <width>
  antenna gain <gain>
 dot11 2.4ghz radio
  power <power_level>
  channel <channel> <width>
```

Configure radio parameters.

## AP Controller Join

```
ap controller
 primary <controller_ip>
 secondary <controller_ip>
```

Configure WLC redundancy.

## AP Reset

```
ap reset
```

Reset AP to factory defaults.

## Display AP

```
show ap all
show ap config
show ap join summary
show ap dot11 5ghz neighbors
```

## Cisco AP Commands Reference

| Cisco | Huawei |
|-------|--------|
| `ap <name> config` | `ap-id` + `ap-name` |
| `ap model` | `ap-model` (similar) |
| `ap group` | `ap-group` |
| `ap location` | `ap-location` (metadata) |
| `ap auth-type` | `ap auth-mode` |
| `ap dot11 5ghz radio` | `radio <radio_id>` |
| `show ap all` | `display wlan ap all` |
| `show ap join summary` | `display wlan ap neighbors` |