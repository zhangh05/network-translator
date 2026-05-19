# Huawei Wireless Service Template Configuration

## Create Service Template

```
wlan
 service-template <id> ssid <ssid_name>
 service-template <id> hide-ssid
```

- `service-template` — create wireless service profile
- `ssid` — broadcast SSID name
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

Assign users to VLAN.

## Bind to AP

```
wlan
 ap-id <id>
 ap-name <name>
 radio <radio_id>
 service-template <id> <id>
```

Bind service template to AP radio.

## Display Service Template

```
display wlan service-template
```

## Huawei Wireless Service Template Commands Reference

| Cisco | Huawei |
|-------|--------|
| `wireless profile policy <name>` | `wlan` + `service-template` |
| `ssid <name>` | `service-template <id> ssid <name>` |
| `security wpa psk` | `security wpa2 psk pass-phrase` |
| `vlan <id>` | `vlan <vlan_id>` |
| `hide ssid` | `hide-ssid` |
| `ap profile` | `ap-id` + `radio` |