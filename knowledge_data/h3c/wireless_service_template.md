# H3C Wireless Service Template Configuration

## Create Service Template

```
wlan
 service-template <id> ssid <ssid_name>
 service-template <id> hide-ssid
```

- `service-template` — create wireless profile
- `ssid` — broadcast SSID
- `hide-ssid` — disable SSID broadcast

## Security Settings

```
wlan
 service-template <id> security wpa2 psk pass-phrase <password> aes
```

WPA2-PSK security.

## VLAN Assignment

```
wlan
 service-template <id> vlan <vlan_id>
```

User VLAN assignment.

## Service Template Enable

```
wlan
 service-template <id> enable
```

Activate service template.

## Bind to AP

```
wlan
 ap-id <id>
 ap-name <name>
 radio <radio_id>
 service-template <id> <template_id>
```

Bind to AP radio.

## Display Service Template

```
display wlan service-template
```

## H3C Wireless Service Template Commands Reference

| Cisco | H3C |
|-------|-----|
| `wireless profile policy` | `wlan` + `service-template` |
| `ssid <name>` | `service-template <id> ssid <name>` |
| `security wpa2 psk` | `security wpa2 psk pass-phrase` |
| `client vlan` | `vlan <vlan_id>` |
| `hide ssid` | `hide-ssid` |
| `ap profile` | `ap-id` + `radio` |
| `show wlan` | `display wlan service-template` |