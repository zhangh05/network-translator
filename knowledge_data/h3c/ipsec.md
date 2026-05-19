# H3C IPsec Configuration

## IKE Proposal

```
ike proposal <id>
 authentication-algorithm <md5|sha1|sha2-256>
 encryption-algorithm <des|3des|aes-128|aes-256>
 dh <group1|group2|group5|group14>
 sa duration <seconds>
```

- `dh` — Diffie-Hellman group
- `sa duration` — SA lifetime

## IKE Peer

```
ike peer <name>
 ike-proposal <proposal_id>
 remote-address <ip>
 pre-shared-key <key>
```

- `remote-address` — peer gateway
- `pre-shared-key` — PSK authentication

## IPsec Proposal

```
ipsec proposal <name>
 encapsulation-mode <tunnel|transport>
 esp authentication-algorithm <md5|sha1|sha2-256>
 esp encryption-algorithm <des|3des|aes-128|aes-256>
```

- `encapsulation-mode tunnel` — full encapsulation

## IPsec Policy

```
ipsec policy <name> <seq> isakmp
 security acl <acl_id>
 ike-peer <peer_name>
 proposal <proposal_name>
```

- `security acl` — interesting traffic
- `ike-peer` — IKE peer binding
- `proposal` — IPsec proposal binding

## Apply Policy

```
interface <interface>
 ipsec policy <name>
```

## IPsec Profile

```
ipsec profile <name>
 ike-peer <peer_name>
 proposal <proposal_name>
```

Template-based IPsec.

## H3C IPsec Commands Reference

| Cisco | H3C |
|-------|-----|
| `crypto isakmp policy` | `ike proposal` |
| `crypto isakmp key` | `ike peer` + `pre-shared-key` |
| `crypto ipsec transform-set` | `ipsec proposal` |
| `crypto map` | `ipsec policy` |
| `crypto ipsec profile` | `ipsec profile` |
| `tunnel mode ipsec` | `tunnel mode ipsec` |
| `set peer` | `remote-address` |
| `match address` | `security acl` |