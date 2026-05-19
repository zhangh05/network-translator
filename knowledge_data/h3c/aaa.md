# H3C AAA Configuration

## VTY Lines (Virtual Terminal)

```
line vty 0 4
 authentication-mode aaa
 user-role network-admin
 undo info-center logbuffer
```

- `line vty 0 4` — range of VTY lines (0-4 or 0-14)
- `authentication-mode aaa` — authenticate via AAA (local or RADIUS/TACACS)
- `user-role network-admin` — level 15 (admin) privilege
- `undo info-center logbuffer` — equivalent of Cisco's `no ip domain lookup`

## AAA Local User

```
aaa
 local-user <name> password cipher <password>
 local-user <name> privilege 3
 local-user <name> service-type telnet ssh
```

- `aaa` — enter AAA view
- `local-user <name> password cipher <password>` — create local user
- `privilege 3` — level 3 (equivalent to admin in H3C role-based model)
- `service-type` — allowed services

## H3C AAA Commands Reference

| Cisco | H3C |
|-------|-----|
| `line vty 0 15` | `line vty 0 4` |
| `login local` | `authentication-mode aaa` |
| `no ip domain lookup` | `undo info-center logbuffer` |
| `username X privilege 15 secret Y` | `aaa` + `local-user X password cipher Y` + `privilege 3` |
