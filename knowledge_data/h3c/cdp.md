# H3C CDP Configuration

## Enable CDP

```
cdp enable
cdp log enable
```

- `cdp enable` — enable globally (not default on H3C)
- `cdp log` — enable logging

## CDP on Interface

```
interface <interface>
 cdp enable
 cdp transparent
```

- `enable` — enable on interface
- `transparent` — pass-through mode

## CDP Timer

```
cdp timer <seconds>
cdp holdtime <seconds>
```

- `timer` — advertisement interval
- `holdtime` — entry lifetime

## CDP Filter

```
undo cdp enable
```

Disable globally.

## LLDP as CDP Alternative

H3C uses LLDP as primary neighbor discovery. CDP is available for Cisco compatibility.

## Display CDP

```
display cdp interface
display cdp neighbor
display cdp statistics
```

## H3C CDP Commands Reference

| Cisco | H3C |
|-------|-----|
| `cdp run` | `cdp enable` (globally) |
| `cdp enable` (interface) | `cdp enable` (interface) |
| `show cdp neighbors` | `display cdp neighbor` |
| `show cdp interface` | `display cdp interface` |
| `show cdp entry` | `display cdp neighbor detail` |
| `cdp timer` | `cdp timer` |
| `cdp holdtime` | `cdp holdtime` |
| `no cdp run` | `undo cdp enable` |