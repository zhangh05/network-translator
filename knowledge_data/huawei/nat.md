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

## ASA-Specific: Interface Mapping / zone

Cisco ASA uses `nameif` and `security-level` for interface context. **Never** output these in Huawei VRP.

| ASA Concept | Huawei Equivalent |
|-------------|-------------------|
| `nameif inside` on interface | `firewall zone trust` + `add interface <interface>` |
| `nameif outside` on interface | `firewall zone untrust` + `add interface <interface>` |
| `security-level <n>` on interface | `set priority <n>` in firewall zone |
| `object network <name>` | `ip address-set <name>` or `acl number <n>` |
| `access-group <name> in interface <if>` | `packet-filter <acl> inbound` or `security-policy` |

**Never** output `nameif`, `security-level`, `object network`, `access-group` in Huawei VRP output.
These are Cisco ASA-specific and are not valid in Huawei command syntax.

## ASA Source Static / Server NAT Translation

ASA NAT with object network reference:
```
object network WEB_SERVER
 host 10.0.0.10
nat (inside,outside) source static WEB_SERVER interface service tcp www www
```
→ Huawei equivalent:
```
nat server protocol tcp global current-interface 80 inside 10.0.0.10 80
```

ASA server NAT with interface reference:
```
nat (inside,outside) source static WEB_SERVER interface service tcp www www
```
→ Huawei equivalent:
```
nat server protocol tcp global current-interface 80 inside 10.0.0.10 80
```

- **No direct Huawei equivalent** for `nat (inside,outside) source static <obj> interface service` exists fully.
- When the global IP is not explicitly given or `interface` is used as global, Huawei VRP requires an explicit IP or `current-interface` keyword.
- Missing information (interface name/zone, global IP) → `# MANUAL_REVIEW` annotation on the line.
- **Never** output `object network` in Huawei output.

## Interface NAT / Port Forwarding

```
nat (inside,outside) source dynamic <obj> <pool>
```
→ Huawei equivalent:
```
nat address-group <id> <start> <end>
acl number <n>
 rule permit source <net> <wildcard>
nat outbound <acl_number> address-group <id>
```

- Each `object network` from ASA must be converted to ACL rules or address-set in Huawei.
- **Never** leave `object network` in the output.

## Huawei NAT Commands Reference

| Cisco IOS | Huawei |
|-----------|--------|
| `ip nat inside source list <acl>` | `nat outbound <acl>` |
| `ip nat inside source list <acl> overload` | `nat outbound <acl> overload` |
| `ip nat pool <name> <start> <end>` | `nat address-group <id> <start> <end>` |
| `ip nat inside source static <local> <global>` | `nat static global <global> inside <local>` |
| `ip nat inside source static tcp <local> <port> <global> <port>` | `nat server protocol tcp global <global> <port> inside <local> <port>` |
| `ip nat service list <acl> alg dns` | `nat alg dns enable` |

| Cisco ASA | Huawei |
|-----------|--------|
| `nat (inside,outside) source static <obj> <obj>` | `nat static global <global> inside <local>` |
| `nat (inside,outside) source static <obj> interface service tcp <port> <port>` | `nat server protocol tcp global current-interface <port> inside <local> <port>` |
| `object network <name> host/subnet/range` | `ip address-set <name>` or `acl number <n>` |
| `nameif <name>` | `firewall zone <name>` + `add interface` |
| `security-level <n>` | `set priority <n>` in firewall zone |
| `access-group <name> in interface <if>` | `packet-filter <acl> inbound` |