# H3C Tunnel Configuration

## GRE Tunnel

```
interface Tunnel0
 ip address <tunnel_ip> <mask>
 tunnel mode gre
 source <src_ip>
 destination <dest_ip>
```

- `tunnel mode gre` — GRE encapsulation
- `source` / `destination` — tunnel endpoints

## IPsec Tunnel

```
interface Tunnel0
 ip address <tunnel_ip> <mask>
 tunnel mode ipsec
 source <src_ip>
 destination <dest_ip>
```

IPsec tunnel mode.

## Tunnel Protection

```
interface Tunnel0
 tunnel protection ipsec profile <profile_name>
```

Bind IPsec profile.

## Apply to Physical Interface

```
interface <physical_interface>
 ip address <ip> <mask>
```

Physical interface for tunnel termination.

## Display Tunnel

```
display interface Tunnel
display tunnel-info
```

## H3C Tunnel Commands Reference

| Cisco | H3C |
|-------|-----|
| `interface Tunnel0` | `interface Tunnel0` |
| `tunnel source <ip>` | `source <ip>` |
| `tunnel destination <ip>` | `destination <ip>` |
| `tunnel mode gre ip` | `tunnel mode gre` |
| `tunnel mode ipsec ipv4` | `tunnel mode ipsec` |
| `tunnel protection ipsec profile` | `tunnel protection ipsec profile` |
| `show interfaces tunnel` | `display interface Tunnel` |