# Huawei DHCP Configuration

## DHCP Address Pool

```
dhcp enable
ip pool <pool_name>
 gateway-list <x.x.x.x>
 network <network> mask <mask>
 excluded-ip-address <start> <end>
 lease day <days>
 dns-list <primary> [secondary]
```

- `dhcp enable` — enable DHCP server globally
- `ip pool <pool_name>` — create a DHCP address pool
- `gateway-list` — set default gateway for clients
- `network` — network range for allocation
- `excluded-ip-address` — IPs to exclude from pooling
- `lease` — lease duration (default 1 day)
- `dns-list` — primary and secondary DNS servers

## Interface Binding

```
interface <interface>
 ip address <ip> <mask>
 dhcp select global
```

Bind an interface to use the global DHCP pool.

## DHCP Relay

```
dhcp enable
interface <interface>
 ip address <ip> <mask>
 dhcp select relay
 dhcp relay server-ip <relay_ip>
```

- `dhcp relay server-ip` — IP of external DHCP server

## DHCP Security

```
dhcp server ping packet <count>
dhcp server ping timeout <ms>
```

Prevent IP conflict by pinging before allocation.

## Huawei DHCP Commands Reference

| Cisco | Huawei |
|-------|--------|
| `ip address pool <name>` | `dhcp select global` / `ip pool <name>` |
| `network <net> <mask>` | `network <net> mask <mask>` |
| `default-router <gw>` | `gateway-list <gw>` |
| `dns-server <ip>` | `dns-list <ip>` |
| `lease <days>` | `lease day <days>` |
| `ip helper-address <ip>` | `dhcp relay server-ip <ip>` |
| `no ip dhcp conflict logging` | `dhcp server ping packet 0` |