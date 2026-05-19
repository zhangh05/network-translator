# Cisco Tunnel Configuration

## GRE Tunnel

```
interface Tunnel0
 ip address <tunnel_ip> <mask>
 tunnel source <src_ip>
 tunnel destination <dest_ip>
 tunnel mode gre ip
```

- `tunnel source` — local tunnel endpoint
- `tunnel destination` — remote tunnel endpoint
- `tunnel mode gre ip` — GRE over IP

## IPsec Tunnel (Crypto Map)

```
interface Tunnel0
 ip address <tunnel_ip> <mask>
 tunnel source <src_ip>
 tunnel destination <dest_ip>
 tunnel mode ipsec ipv4
```

## Crypto Map Configuration

```
crypto isakmp policy <priority>
 crypto isakmp key <key> address <peer_ip>
crypto ipsec transform-set <name> esp-aes esp-sha-hmac
crypto map <map_name> <seq> ipsec-isakmp
 set peer <peer_ip>
 set transform-set <name>
 match address <acl_id>
```

- `crypto isakmp` — IKE Phase 1
- `crypto ipsec` — IPE Phase 2

## Apply Crypto Map

```
interface <interface>
 crypto map <map_name>
```

## Tunnel Protection (IPsec Virtual Tunnel)

```
interface Tunnel0
 tunnel protection ipsec profile <profile_name>
```

Bind IPsec profile (VTI style).

## Display Tunnel

```
show interfaces tunnel
show crypto ipsec sa
show crypto isakmp sa
```

## Cisco Tunnel Commands Reference

| Cisco | Huawei |
|-------|--------|
| `interface Tunnel0` | `interface Tunnel0` |
| `tunnel source <ip>` | `source <ip>` |
| `tunnel destination <ip>` | `destination <ip>` |
| `tunnel mode gre ip` | `tunnel-protocol gre` |
| `tunnel mode ipsec ipv4` | `tunnel-protocol ipsec` |
| `tunnel protection ipsec profile` | `tunnel protection ipsec profile` |
| `crypto map` | `ipsec policy` |
| `show interfaces tunnel` | `display interface Tunnel` |