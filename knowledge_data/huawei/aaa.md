# Huawei AAA Configuration

## VTY Lines (Virtual Terminal)

```
user-interface vty 0 4
 authentication-mode aaa
 protocol inbound ssh
 undo info-center enable
```

- `user-interface vty 0 4` — range of VTY lines (0-4 or 0-14)
- `authentication-mode aaa` — authenticate via AAA (local or RADIUS/TACACS)
- `protocol inbound ssh` — allow SSH (use `all` for ssh+telnet)
- `undo info-center enable` — disable logging/info-center (equivalent of Cisco's `no ip domain lookup`)

## AAA Local User

```
aaa
 local-user <name> password cipher <password>
 local-user <name> privilege level 15
 local-user <name> service-type telnet ssh
```

- `aaa` — enter AAA view
- `local-user <name> password cipher <password>` — create local user with encrypted password
- `local-user <name> privilege level 15` — level 15 (admin)
- `local-user <name> service-type telnet ssh` — allowed services

## Huawei AAA Commands Reference

| Cisco | Huawei |
|-------|--------|
| `line vty 0 15` | `user-interface vty 0 4` |
| `login local` | `authentication-mode aaa` |
| `transport input ssh telnet` | `protocol inbound ssh` + `service-type` |
| `no ip domain lookup` | `undo info-center enable` |
| `username X privilege 15 secret Y` | `local-user X password cipher Y` + `local-user X privilege level 15` |
