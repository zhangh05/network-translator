# Cisco NAT Configuration (Firewall Domain)

## Inside Global NAT

```
interface <inside_interface>
 ip nat inside
interface <outside_interface>
 ip nat outside
ip nat inside source list <acl_id> interface <outside_interface> overload
```

- `ip nat inside` — mark inside interface
- `ip nat outside` — mark outside interface
- `inside source list` — define internal network

## NAT Pool

```
ip nat pool <pool_name> <start_ip> <end_ip> netmask <mask>
ip nat inside source list <acl_id> pool <pool_name> overload
```

Address pool for NAT.

## Static NAT

```
ip nat inside source static <local_ip> <global_ip>
ip nat inside source static tcp <local_ip> <port> <global_ip> <port>
```

One-to-one mapping.

## PAT (Port Address Translation)

```
ip nat inside source list <acl_id> interface <interface> overload
```

Many-to-one with port multiplexing.

## Route Map NAT

```
ip nat inside source route-map <map_name> interface <interface>
route-map <map_name> permit <seq>
 match interface <interface>
```

Policy-based NAT.

## NAT Translation Timeout

```
ip nat translation timeout <seconds>
ip nat translation udp-timeout <seconds>
ip nat translation dns-timeout <seconds>
ip nat translation tcp-timeout <seconds>
```

Adjust translation timeouts.

## Cisco NAT Commands Reference

| Cisco | Huawei |
|-------|--------|
| `ip nat inside` | `dhcp select global` (different model) |
| `ip nat outside` | `dhcp select global` |
| `ip nat inside source list <acl>` | `nat outbound <acl>` |
| `ip nat inside source list <acl> overload` | `nat outbound <acl> overload` |
| `ip nat pool <name> <start> <end>` | `nat address-group` |
| `ip nat inside source static` | `nat static global inside` |
| `ip nat inside source static tcp` | `nat server protocol tcp` |
| `show ip nat translations` | `display nat` |