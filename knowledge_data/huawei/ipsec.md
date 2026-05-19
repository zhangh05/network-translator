# Huawei IPsec Configuration

## IKE Proposal

```
ike proposal <id>
 authentication-algorithm <md5|sha1|sha2-256>
 encryption-algorithm <des|3des|aes-128|aes-256>
 dh <group1|group2|group5|group14>
 sa duration <seconds>
```

- `dh` — Diffie-Hellman group for key exchange
- `sa duration` — SA lifetime

## IKE Peer

```
ike peer <name>
 ike-proposal <proposal_id>
 remote-address <ip>
 pre-shared-key <key>
```

- `remote-address` — peer gateway IP
- `pre-shared-key` — PSK authentication

## IPsec Proposal

```
ipsec proposal <name>
 encapsulation-mode <tunnel|transport>
 esp authentication-algorithm <md5|sha1|sha2-256>
 esp encryption-algorithm <des|3des|aes-128|aes-256>
```

- `encapsulation-mode tunnel` — full encapsulation (default)

## IPsec Policy

```
ipsec policy <name> <seq> isakmp
 security acl <acl_id>
 ike-peer <peer_name>
 proposal <proposal_name>
```

- `security acl` — ACL defining interesting traffic
- `ike-peer` — bind IKE peer
- `proposal` — bind IPsec proposal

## Apply Policy

```
interface <interface>
 ipsec policy <name>
```

## IPsec Profile (Template)

```
ipsec profile <name>
 ike-peer <peer_name>
 proposal <proposal_name>
```

## Huawei IPsec Commands Reference

| Cisco | Huawei |
|-------|--------|
| `crypto isakmp policy <id>` | `ike proposal <id>` |
| `crypto isakmp key <key> address <ip>` | `ike peer <name>` + `pre-shared-key` |
| `crypto ipsec transform-set <name>` | `ipsec proposal <name>` |
| `crypto map <name> <seq> ipsec-isakmp` | `ipsec policy <name> <seq> isakmp` |
| `crypto map <name> interface` | `ipsec policy <name>` on interface |
| `crypto ipsec profile` | `ipsec profile` |