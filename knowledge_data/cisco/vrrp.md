# Cisco VRRP Configuration

## Basic VRRP

```
interface <interface>
 vrrp <group_id> ip <virtual_ip>
 vrrp <group_id> priority <priority>
 vrrp <group_id> preempt
 vrrp <group_id> authentication <text>
```

- `vrrp` — VRRP group number
- `ip` — virtual gateway address
- `priority` — 1-254 (default 100)
- `preempt` — enable preemption

## Priority Tracking

```
vrrp <group_id> track <interface> decrement <value>
vrrp <group_id> track <track_object> priority <value>
```

- `track interface` — failover on interface failure
- `decrement` — priority reduction value

## Timers

```
vrrp <group_id> timers advertise <seconds>
vrrp <group_id> timers learning
```

- `advertise` — advertisement interval
- `learning` — learn peer timers

## Version 3

```
vrrp version 3
vrrp <group_id> ip <virtual_ip> version 3
```

VRRPv3 for IPv6.

## Load Balancing

```
vrrp <group_id> load-balancing host
```

Enable load balancing mode.

## Display VRRP

```
show vrrp
show vrrp interface <interface>
show vrrp brief
```

## Cisco VRRP Commands Reference

| Cisco | Huawei |
|-------|--------|
| `vrrp <id> ip <vip>` | `vrrp vrid <id> virtual-ip <vip>` |
| `vrrp <id> priority <pri>` | `vrrp vrid <id> priority <pri>` |
| `vrrp <id> preempt` | `vrrp vrid <id> preempt-mode` |
| `vrrp <id> track <int> decrement <val>` | `vrrp vrid <id> track interface <int> reduced <val>` |
| `vrrp <id> authentication` | `vrrp vrid <id> authentication-mode simple` |
| `vrrp <id> timers advertise` | `vrrp vrid <id> timer advertise` |
| `show vrrp` | `display vrrp` |