# Huawei VRRP Configuration

## Basic VRRP

```
interface <interface>
 vrrp vrid <id> virtual-ip <vip>
 vrrp vrid <id> priority <priority>
 vrrp vrid <id> preempt-mode timer delay <sec>
```

- `vrrp vrid` — VRRP group ID (1-255)
- `virtual-ip` — virtual gateway IP
- `priority` — router priority (default 100, higher wins)
- `preempt-mode` — master election behavior

## Track Interface/Route

```
vrrp vrid <id> track interface <interface> reduced <value>
vrrp vrid <id> track interface <interface>switchover
```

- `track interface` — failover on interface loss
- `reduced` — priority reduction on failure

## Track BFD

```
vrrp vrid <id> track bfd-session session-name <name> reduced <value>
```

BFD tracking for faster failover.

## Authentication

```
vrrp vrid <id> authentication-mode simple <password>
vrrp vrid <id> authentication-mode md5
```

Secure VRRP communication.

## VRRP Timers

```
vrrp vrid <id> timer advertise <seconds>
vrrp vrid <id> timer learning
```

- `timer advertise` — advertisement interval (default 1s)
- `timer learning` — learn peer timers

## Display VRRP

```
display vrrp
display vrrp interface <interface>
```

## Huawei VRRP Commands Reference

| Cisco | Huawei |
|-------|--------|
| `standby <id> ip <vip>` | `vrrp vrid <id> virtual-ip <vip>` |
| `standby <id> priority <pri>` | `vrrp vrid <id> priority <pri>` |
| `standby <id> preempt` | `vrrp vrid <id> preempt-mode` |
| `standby <id> track <int> decrement <val>` | `vrrp vrid <id> track interface <int> reduced <val>` |
| `standby <id> authentication <text>` | `vrrp vrid <id> authentication-mode simple` |
| `show vrrp` | `display vrrp` |
| `show vrrp interface` | `display vrrp interface` |