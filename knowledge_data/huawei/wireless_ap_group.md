# Huawei Wireless AP Group Configuration

## Create AP Group

```
wlan
 ap-group <group_name>
```

Create an AP group.

## Add AP to Group

```
wlan
 ap-id <id>
 ap-name <name>
 ap-group <group_name>
```

Assign AP to group.

## Group Radio Configuration

```
wlan
 ap-group <group_name>
 regulatory-domain-profile <domain_profile>
 radio <radio_id>
 radio-type <80211gn|80211an|80211ac|80211ax>
```

- `radio` — configure radio settings
- `radio-type` — 802.11 standard variant

## AP Group Service Template

```
wlan
 ap-group <group_name>
 radio <radio_id>
 service-template <id> <template_id>
```

Bind service template to group radio.

## AP Group Regulatory Domain

```
wlan
 regulatory-domain-profile <name>
 country-code <country>
```

Set regulatory domain.

## Display AP Group

```
display wlan ap-group
display wlan ap all
```

## Huawei AP Group Commands Reference

| Cisco | Huawei |
|-------|--------|
| `ap group <name>` | `ap-group <group_name>` |
| `ap <name>加入 group` | `ap-id` + `ap-group` |
| `ap-group <name> radio <id>` | `ap-group <name> radio <id>` |
| `ap dot11 radio <id>` | `radio <radio_id>` |
| `ap dot11 radio <id> radio-type` | `radio-type` |
| `show ap groups` | `display wlan ap-group` |