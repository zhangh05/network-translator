# H3C Wireless AP Group Configuration

## Create AP Group

```
wlan
 ap-group <group_name>
```

Create AP group.

## AP Group Configuration

```
wlan
 ap-group <group_name>
 regulatory-domain-profile <domain_profile>
 radio <radio_id>
 radio-type <80211gn|80211an|80211ac|80211ax>
 service-template <id> <template_id>
```

- `radio` — configure radio
- `radio-type` — 802.11 variant
- `service-template` — bind wireless profile

## Add AP to Group

```
wlan
 ap-id <id>
 ap-name <name>
 ap-group <group_name>
```

Assign AP to group.

## AP Group Domain

```
wlan
 regulatory-domain-profile <name>
 country-code <country>
```

Regulatory domain.

## Display AP Group

```
display wlan ap-group
display wlan ap all
```

## H3C AP Group Commands Reference

| Cisco | H3C |
|-------|-----|
| `ap group <name>` | `ap-group <group_name>` |
| `ap <name> group <group>` | `ap-id` + `ap-group` |
| `ap-group <name> radio` | `ap-group <name> radio` |
| `ap dot11 radio` | `radio <radio_id>` |
| `ap-group <name> radio-type` | `radio-type` |
| `show ap groups` | `display wlan ap-group` |
| `show ap all` | `display wlan ap all` |