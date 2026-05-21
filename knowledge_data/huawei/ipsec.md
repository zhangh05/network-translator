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

## ACL / Interesting Traffic

Huawei IPsec uses ACL to define interesting traffic (not `object network` or `object-group`).

```
acl number <3000-3999>
 rule <seq> permit ip source <net> <wildcard> destination <net> <wildcard>
```

- ACL must be **numbered** (3000-3999 for IP).
- ACL is referenced by `ipsec policy <name> <seq> isakmp` via `security acl <acl_id>`.
- Each `object network <name> subnet <ip> <mask>` from ASA maps to an ACL `rule permit ip source <src> destination <dst>`.
- Each `object-group network <name>` maps to multiple ACL rules or a broader rule per subnet.
- **Never** output `object network` or `object-group` in Huawei VRP target — these are Cisco ASA syntax and have no direct equivalent in Huawei IPsec context.

## Interface / Zone

Huawei VRP uses `firewall zone` (USG) to group interfaces, not `nameif`/`security-level`.

```
firewall zone <name>
 add interface <interface>
 quit
```

- `nameif inside/outside` on ASA → `firewall zone trust/untrust` with `add interface` in Huawei.
- `security-level <n>` on ASA → `set priority <n>` in Huawei firewall zone.
- **Never** output `nameif` or `security-level` in Huawei VRP target.

## Huawei IPsec Commands Reference

| Cisco | Huawei |
|-------|--------|
| `crypto isakmp policy <id>` | `ike proposal <id>` |
| `crypto isakmp key <key> address <ip>` | `ike peer <name>` + `pre-shared-key` |
| `crypto ipsec transform-set <name>` | `ipsec proposal <name>` |
| `crypto map <name> <seq> ipsec-isakmp` | `ipsec policy <name> <seq> isakmp` |
| `crypto map <name> interface` | `ipsec policy <name>` on interface |
| `crypto ipsec profile` | `ipsec profile` |
| `object network <name> subnet <ip> <mask>` | `acl number <3000-3999>` + `rule permit ip` |
| `access-list <id> extended permit ip <src> <dst>` | `acl number <3000-3999>` + `rule permit ip source <src> <dst>` |