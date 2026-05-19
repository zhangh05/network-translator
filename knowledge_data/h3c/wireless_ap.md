# H3C Wireless AP Configuration

## Create AP

```
wlan
 ap-id <id>
 ap-mac <mac_address>
 ap-name <name>
 ap-model <model>
 ap-sn <serial_number>
```

- `ap-mac` — AP MAC for identification
- `ap-name` — administrative name
- `ap-sn` — serial number

## AP Authentication

```
wlan
 ap auth-mode <mac-auth|sn-auth|no-auth>
```

MAC, serial, or no authentication.

## AP Serial Configuration

```
wlan
 ap-id <id>
 ap serial-number <serial>
```

Configure via serial.

## Radio Configuration

```
wlan
 ap-id <id>
 radio <radio_id>
 radio-type <80211gn|80211an|80211ac|80211ax>
 max-power <power>
 channel <channel> <width>
```

- `max-power` — transmit power
- `channel` — channel assignment

## AP Provisioning

```
wlan
 ap-id <id>
 ap provision
```

Manual provisioning.

## Display AP

```
display wlan ap all
display wlan ap neighbors
```

## H3C AP Commands Reference

| Cisco | H3C |
|-------|-----|
| `ap <name> config` | `ap-id` + `ap-name` |
| `ap serial-number` | `ap-sn` |
| `ap auth-type` | `ap auth-mode` |
| `ap dot11 5ghz radio` | `radio <radio_id>` |
| `show ap all` | `display wlan ap all` |
| `show ap join summary` | `display wlan ap neighbors` |