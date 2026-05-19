# H3C DHCP Configuration

## Enable DHCP

```
dhcp enable
dhcp server forbidden-ip <start> <end>
```

Enable DHCP globally and exclude addresses.

## DHCP Address Pool

```
dhcp server ip-pool <pool_name>
 network <network> mask <mask>
 gateway-list <x.x.x.x>
 dns-list <primary> [secondary]
 expired <days> <hours>
```

- `dhcp server ip-pool` — create address pool
- `network` — network range for allocation
- `gateway-list` — default gateway
- `dns-list` — DNS servers
- `expired` — lease duration

## Interface Configuration

```
interface <interface>
 ip address <ip> <mask>
 dhcp select global
 dhcp server apply ip-pool <pool_name>
```

Bind interface to global or specific pool.

## DHCP Relay

```
dhcp enable
interface <interface>
 ip address <ip> <mask>
 dhcp select relay
 dhcp relay server-address <relay_ip>
```

- `dhcp relay server-address` — external DHCP server

## DHCP Snooping

```
dhcp snooping enable
dhcp snooping vlan <vlan>
dhcp snooping trust
```

Security to prevent rogue DHCP servers.

## H3C DHCP Commands Reference

| Cisco | H3C |
|-------|-----|
| `ip dhcp pool <name>` | `dhcp server ip-pool <name>` |
| `network <net> <mask>` | `network <net> mask <mask>` |
| `default-router <gw>` | `gateway-list <gw>` |
| `dns-server <ip>` | `dns-list <ip>` |
| `lease <days>` | `expired <days>` |
| `ip helper-address <ip>` | `dhcp relay server-address <ip>` |
| `ip dhcp excluded-address` | `dhcp server forbidden-ip` |
| `ip dhcp snooping` | `dhcp snooping enable` |