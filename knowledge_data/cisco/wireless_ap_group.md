# Cisco Wireless AP Group Configuration

## AP Group

```
ap group <group_name>
```

Create AP group.

## AP Group WLAN Assignment

```
ap group <group_name>
 wlan <wlan_name>服务质量 <qos_policy>
```

Assign WLAN to group.

## AP Group Site Tag

```
ap group <group_name>
 site-tag <site_tag_name>
```

Apply site tag.

## AP Group Policy

```
ap group <group_name>
 rf-tag <rf_tag_name>
 policy-tag <policy_tag_name>
```

Apply RF and policy tags.

## Add AP to Group

```
ap <ap_name>
 group <group_name>
```

Assign AP to group.

## AP Group Default Settings

```
wireless default ap-group
 group <group_name>
```

Set default group for new APs.

## AP Group Timeouts

```
ap group <group_name>
 username <user> password <pwd>
```

AP group credentials (统一管理).

## Display AP Group

```
show ap group
show ap groups
show ap group name <name>
```

## Cisco AP Group Commands Reference

| Cisco | Huawei |
|-------|--------|
| `ap group <name>` | `ap-group <group_name>` |
| `ap <name> group <group>` | `ap-id` + `ap-group` |
| `ap group <name> wlan` | `ap-group <name> radio` + `service-template` |
| `ap group <name> rf-tag` | `ap-group <name> radio` |
| `show ap groups` | `display wlan ap-group` |
| `show ap group name` | `display wlan ap-group <name>` |