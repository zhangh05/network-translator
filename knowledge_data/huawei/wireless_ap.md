# Huawei Wireless AP Configuration

## Create AP

```
wlan
 ap-id <id>
 ap-mac <mac_address>
 ap-name <name>
 ap-sn <serial_number>
```

- `ap-mac` — AP MAC address for identification
- `ap-name` — administrative name
- `ap-sn` — serial number

## AP Authentication

```
wlan
 ap auth-mode <mac-auth|sn-auth|no-auth>
 ap-password <password>
```

MAC, serial, or no authentication.

## AP Provisioning

```
wlan
 ap-id <id>
 ap provision
```

Manual AP provisioning.

## Radio Configuration

```
wlan
 ap-id <id>
 radio <radio_id>
 radio-type <80211gn|80211an|80211ac|80211ax>
 max-power <power>
 min-power <power>
 channel <channel> <channel_width>
```

- `radio` — configure radio parameters
- `max-power` / `min-power` — power bounds
- `channel` — channel assignment

## AP Filter

```
wlan
 ap-filter import filter-id <id> ap-mac <mac>
```

Import AP MAC filter list.

## Display AP

```
display wlan ap all
display wlan ap neighbors
```

## Huawei AP Commands Reference

| Cisco | Huawei |
|-------|--------|
| `ap name <name> config-id <id>` | `ap-id <id>` + `ap-name <name>` |
| `ap serial-number` | `ap-sn` |
| `ap authentication` | `ap auth-mode` |
| `show ap all` | `display wlan ap all` |
| `show ap join summary` | `display wlan ap neighbors` |