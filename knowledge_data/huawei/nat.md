# Huawei NAT Configuration

## Basic NAT (Inside Global)

```
acl <number>
 rule permit source <net> <wildcard>
 quit
interface <interface>
 nat outbound <acl_number>
```

- `acl` — define internal network range
- `nat outbound` — apply NAT with ACL

## PAT (Port Address Translation)

```
acl <number>
 rule permit source <net> <wildcard>
 quit
interface <interface>
 nat outbound <acl_number> address-group <group> overload
```

- `overload` — enable PAT (many-to-one)

## NAT Address Pool

```
nat address-group <id> <start_ip> <end_ip>
```

Create address pool for NAT.

## Static NAT

```
nat static global <global_ip> inside <local_ip>
```

One-to-one static mapping.

## Server Mapping

```
nat server protocol <tcp|udp> global <global_ip> <port> inside <local_ip> <port>
```

Port forwarding (like Cisco `nat static`).

## DNSALG

```
nat alg dns enable
```

Enable ALG for DNS translation.

## Huawei NAT Commands Reference

| Cisco | Huawei |
|-------|--------|
| `ip nat inside source list <acl>` | `nat outbound <acl>` |
| `ip nat inside source list <acl> overload` | `nat outbound <acl> overload` |
| `ip nat pool <name> <start> <end>` | `nat address-group <id> <start> <end>` |
| `ip nat inside source static <local> <global>` | `nat static global <global> inside <local>` |
| `ip nat inside source static tcp <local> <port> <global> <port>` | `nat server protocol tcp global <global> <port> inside <local> <port>` |
| `ip nat service list <acl> alg dns` | `nat alg dns enable` |