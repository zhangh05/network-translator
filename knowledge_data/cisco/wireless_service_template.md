# Cisco Wireless Service Template Configuration

## WLAN Profile

```
wireless profile policy <policy_name>
```

Create policy profile.

## WLAN Settings

```
wlan <profile_name> <wlan_id> <ssid_name>
 client vlan <vlan_id>
 security <wpa2|wp3> psk set-key <password>
 no shutdown
```

- `wlan` — create WLAN
- `client vlan` — user VLAN
- `security` — WPA2/WPA3 with PSK

## Policy Profile Settings

```
wireless profile policy <name>
 vlan <vlan_id>
 roam-intra-prof <profile>
 session-timeout <seconds>
 idle-timeout <seconds>
```

## AP Join Policy

```
wireless tag policy <tag_name>
 profile <profile_name>
```

Policy tag for AP.

## RF Tag

```
wireless tag rf <rf_name>
 dot11 5ghz radio <radio_policy>
 dot11 2.4ghz radio <radio_policy>
```

Radio frequency configuration.

## Site Tag

```
wireless tag site <site_name>
 ap-group <ap_group>
```

Site-specific configuration.

## Apply to AP

```
ap <ap_name>
 tag policy <policy_tag>
 tag rf <rf_tag>
```

Assign tags to AP.

## Display Wireless

```
show wlan summary
show wireless profile policy
show ap config
```

## Cisco Wireless Service Template Commands Reference

| Cisco | Huawei |
|-------|--------|
| `wireless profile policy <name>` | `wlan` + `service-template` |
| `wlan <name> <id> <ssid>` | `service-template <id> ssid <name>` |
| `client vlan <vlan>` | `vlan <vlan_id>` |
| `security wpa2 psk` | `security wpa2 psk pass-phrase` |
| `wireless tag policy` | `ap-group` |
| `show wlan` | `display wlan service-template` |