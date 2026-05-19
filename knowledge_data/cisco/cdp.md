# Cisco CDP Configuration

## Enable CDP

```
cdp run
cdp holdtime <seconds>
cdp timer <seconds>
```

- `cdp run` — enable CDP globally
- `holdtime` — hold time for received entries
- `timer` — update interval

## CDP on Interface

```
interface <interface>
 cdp enable
 cdp vlan-name
```

- `cdp enable` — enable on interface
- `vlan-name` — send VLAN name TLV

## Filter CDP Information

```
no cdp run
```

Disable globally.

## CDP Transparent Mode

```
cdp transparent
```

Pass-through mode for switches.

## LLDP as Alternative

Cisco recommends LLDP (IEEE 802.1AB) as CDP replacement:

```
lldp run
lldp run
```

## Display CDP

```
show cdp
show cdp neighbors
show cdp neighbors detail
show cdp interface
show cdp entry
```

## Cisco CDP Commands Reference

| Cisco | Huawei |
|-------|--------|
| `cdp run` | `cdp enable` (globally) |
| `cdp enable` (interface) | `cdp enable` (interface) |
| `show cdp neighbors` | `display cdp neighbor` |
| `show cdp interface` | `display cdp interface` |
| `show cdp entry` | `display cdp neighbor detail` |
| `cdp timer` | `cdp timer` |
| `cdp holdtime` | `cdp holdtime` |
| `no cdp run` | `undo cdp enable` |