# Cisco IPsec Configuration

## IKEv1 ISAKMP Policy

```
crypto isakmp policy <priority>
 authentication pre-share
 encryption <aes|aes-256|3des>
 hash <sha|sha256|md5>
 group <1|2|5|14>
 lifetime <seconds>
```

- `priority` — lower = higher preference
- `authentication pre-share` — PSK
- `group` — DH group

## IKEv1 Pre-Shared Key

```
crypto isakmp key <key> address <peer_ip> [mask]
crypto isakmp key <key> hostname <peer_fqdn>
```

Configure PSK for peer.

## IKEv2

```
crypto isakmp policy <priority>
 encryption aes
 integrity sha256
 group 14
crypto isakmp profile <name>
  keyring <keyring_name>
  match identity address <peer_ip>
```

## Transform Set

```
crypto ipsec transform-set <name> esp-aes esp-sha-hmac
 crypto ipsec transform-set <name> mode <tunnel|transport>
```

- `esp-aes` — encryption
- `esp-sha-hmac` — authentication

## Crypto Map

```
crypto map <map_name> <seq> ipsec-isakmp
 set peer <peer_ip>
 set pfs <group1|group2|group14>
 set transform-set <name>
 match address <acl_id>
```

- `set peer` — remote peer
- `match address` — interesting traffic ACL

## IPsec Virtual Tunnel Interface (VTI)

```
interface Tunnel0
 ip address <tunnel_ip> <mask>
 tunnel source <src_ip>
 tunnel destination <dest_ip>
 tunnel mode ipsec ipv4
```

## Apply Crypto Map

```
interface <interface>
 crypto map <map_name>
```

## IPsec Profile (VTI)

```
crypto ipsec profile <name>
 set transform-set <name>
 set pfs group14
```

## Cisco IPsec Commands Reference

| Cisco | Huawei |
|-------|--------|
| `crypto isakmp policy` | `ike proposal` |
| `crypto isakmp key` | `ike peer` + `pre-shared-key` |
| `crypto ipsec transform-set` | `ipsec proposal` |
| `crypto map` | `ipsec policy` |
| `crypto ipsec profile` | `ipsec profile` |
| `tunnel mode ipsec` | `tunnel-protocol ipsec` |
| `set peer` | `remote-address` |
| `match address` | `security acl` |