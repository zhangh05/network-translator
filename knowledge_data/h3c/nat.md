# H3C NAT Configuration

## Basic NAT

```
acl <number>
 rule permit source <ip> <wildcard>
 quit
interface <interface>
 nat outbound <acl_number>
```

- `acl` — define internal network
- `nat outbound` — apply NAT

## PAT (Overload)

```
acl <number>
 rule permit source <network> <wildcard>
 quit
interface <interface>
 nat outbound <acl_number> address-group <group> overload
```

- `overload` — enable port translation

## NAT Address Group

```
nat address-group <id> <start_ip> <end_ip>
```

Address pool for NAT.

## Static NAT

```
nat static enable
interface <interface>
 nat static inbound <global_ip> <local_ip>
 nat static outbound <local_ip> <global_ip>
```

One-to-one mapping.

## Server Mapping (Port Forwarding)

```
interface <interface>
 nat server protocol <tcp|udp> global <global_ip> <port> inside <local_ip> <port>
```

Port-based forwarding.

## DNS ALG

```
nat alg dns
```

Enable DNS ALG for translation.

## H3C NAT Commands Reference

| Cisco | H3C |
|-------|-----|
| `ip nat inside source list <acl>` | `nat outbound <acl>` |
| `ip nat inside source list <acl> overload` | `nat outbound <acl> overload` |
| `ip nat pool <name> <start> <end>` | `nat address-group <start> <end>` |
| `ip nat inside source static` | `nat static inbound/outbound` |
| `ip nat inside source static tcp` | `nat server protocol tcp` |
| `ip nat service list alg dns` | `nat alg dns` |