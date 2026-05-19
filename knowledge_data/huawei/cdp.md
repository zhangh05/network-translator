# Huawei CDP Configuration

## Enable CDP

```
cdp enable
cdp log enable
```

- `cdp enable` — enable CDP globally (not default on Huawei)
- `cdp log` — enable CDP logging

## CDP on Interface

```
interface <interface>
 cdp enable
 cdp transparent enable
```

- `cdp enable` — enable on specific interface
- `transparent` — pass-through mode

## CDP Timer

```
cdp timer <seconds>
cdp holdtime <seconds>
```

- `timer` — advertisement interval
- `holdtime` — entry lifetime

## LLDP vs CDP

Huawei uses LLDP as the CDP equivalent. CDP must be explicitly enabled.

## Display CDP

```
display cdp interface
display cdp neighbor
display cdp statistics
```

## Huawei CDP Commands Reference

| Cisco | Huawei |
|-------|--------|
| `cdp enable` | `cdp enable` (globally) |
| `cdp run` | `cdp enable` globally + per-interface |
| `show cdp neighbors` | `display cdp neighbor` |
| `show cdp interface` | `display cdp interface` |
| `show cdp entry` | `display cdp neighbor detail` |
| `cdp timer` | `cdp timer` |
| `cdp holdtime` | `cdp holdtime` |