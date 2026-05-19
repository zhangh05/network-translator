# Cisco AAA Configuration

## VTY Lines (Virtual Terminal)

```
line vty 0 4
 login local
 transport input ssh telnet
 no ip domain lookup
```

- `line vty 0 15` — range of VTY lines (0-4 or 0-15)
- `login local` — authenticate using local username database
- `transport input ssh telnet` — allow both SSH and Telnet
- `no ip domain lookup` — disable DNS resolution on VTY lines

## Local User

```
username <name> privilege <0-15> secret <password>
```

- `privilege 15` — level 15 (admin)
- `secret` — type 5 (MD5) hashed password

## Domain Lookup

```
no ip domain lookup
```

- Disables default DNS name resolution globally
