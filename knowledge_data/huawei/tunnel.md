# Huawei Tunnel Configuration

## GRE Tunnel

```
interface Tunnel0
 tunnel-protocol gre
 source <src_ip>
 destination <dest_ip>
 ip address <tunnel_ip> <mask>
```

- `tunnel-protocol gre` — GRE encapsulation
- `source` / `destination` — tunnel endpoints

## IPsec Tunnel

```
interface Tunnel0
 tunnel-protocol ipsec
 source <src_ip>
 destination <dest_ip>
 ip address <tunnel_ip> <mask>
```

IPsec tunnel mode with encryption.

## Tunnel Security

```
interface Tunnel0
 tunnel protection ipsec profile <profile_name>
```

Bind IPsec profile for encryption.

## Apply to Interface

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

## Huawei Tunnel Commands Reference

| Cisco | Huawei |
|-------|--------|
| `interface Tunnel0` | `interface Tunnel0` |
| `tunnel destination <ip>` | `destination <ip>` |
| `tunnel source <ip>` | `source <ip>` |
| `tunnel mode gre ip` | `tunnel-protocol gre` |
| `tunnel mode ipsec ipv4` | `tunnel-protocol ipsec` |
| `tunnel protection ipsec profile` | `tunnel protection ipsec profile` |
| `show interfaces tunnel` | `display interface Tunnel` |