# Cisco DHCP Configuration

## DHCP Pools

```
ip dhcp pool <pool_name>
 network <network> <subnet_mask>
 default-router <gateway>
 dns-server <primary> [secondary]
 domain-name <domain>
 lease <days> <hours> <minutes>
```

- `network` — address range for allocation
- `default-router` — default gateway for clients
- `dns-server` — DNS servers
- `domain-name` — DNS domain suffix
- `lease` — lease duration

## DHCP Exclusions

```
ip dhcp excluded-address <start_ip> <end_ip>
```

Reserve IPs from pooling.

## DHCP Relay

```
interface <interface>
 ip helper-address <dhcp_server_ip>
```

Relay DHCP requests to server.

## DHCP Conflict Logging

```
ip dhcp conflict logging
```

Record address conflicts.

## DHCP Snooping

```
ip dhcp snooping
ip dhcp snooping vlan <vlan>
ip dhcp snooping trust
```

Security feature to prevent rogue DHCP servers.

## Cisco DHCP Commands Reference

| Cisco | Huawei |
|-------|--------|
| `ip dhcp pool <name>` | `ip pool <name>` + `dhcp enable` |
| `network <net> <mask>` | `network <net> mask <mask>` |
| `default-router <gw>` | `gateway-list <gw>` |
| `dns-server <ip>` | `dns-list <ip>` |
| `lease <days>` | `lease day <days>` |
| `ip helper-address <ip>` | `dhcp relay server-ip <ip>` |
| `ip dhcp excluded-address` | `excluded-ip-address` |
| `ip dhcp snooping` | `dhcp snooping enable` |