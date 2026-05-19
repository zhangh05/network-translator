# H3C VRRP Configuration

## Basic VRRP

```
interface <interface>
 vrrp <group_id> virtual-ip <vip>
 vrrp <group_id> priority <priority>
 vrrp <group_id> preempt-mode
```

- `vrrp` — VRRP group number
- `virtual-ip` — virtual gateway address
- `priority` — 1-254 (default 100, higher wins)
- `preempt-mode` — master election

## Track Interface

```
vrrp <group_id> track interface <interface> reduced <value>
```

Failover on interface failure.

## Track BFD

```
vrrp <group_id> track bfd-session <session_name> reduced <value>
```

BFD-based tracking for fast failover.

## Authentication

```
vrrp <group_id> authentication-mode simple <password>
vrrp <group_id> authentication-mode md5
```

Secure VRRP communication.

## Timers

```
vrrp <group_id> timer advertise <seconds>
```

Advertisement interval (default 1s).

## Load Balancing

```
vrrp load-balancing
```

Enable VRRP load balancing.

## Display VRRP

```
display vrrp
display vrrp interface <interface>
```

## H3C VRRP Commands Reference

| Cisco | H3C |
|-------|-----|
| `vrrp <id> ip <vip>` | `vrrp <id> virtual-ip <vip>` |
| `vrrp <id> priority <pri>` | `vrrp <id> priority <pri>` |
| `vrrp <id> preempt` | `vrrp <id> preempt-mode` |
| `vrrp <id> track <int> decrement <val>` | `vrrp <id> track interface <int> reduced <val>` |
| `vrrp <id> authentication` | `vrrp <id> authentication-mode` |
| `vrrp <id> timers advertise` | `vrrp <id> timer advertise` |
| `show vrrp` | `display vrrp` |