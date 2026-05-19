# H3C System Configuration

## Hostname

```
sysname <hostname>
```

Set device hostname.

## Domain and DNS

```
ip domain-name <domain>
ip domain-lookup
```

DNS configuration.

## AAA Configuration

```
aaa
 local-user <name> password cipher <pwd>
 local-user <name> privilege <level>
 local-user <name> service-type telnet ssh
```

Local user management.

## Time and NTP

```
ntp-server <ip>
ntp-client
clock timezone <zone> <offset>
clock datetime <hh:mm:ss> <YYYY-MM-DD>
```

Time synchronization.

## Logging

```
info-center loghost <ip>
info-center timestamp log date
info-center source <source> channel <channel>
```

Centralized logging.

## License Management

```
license activate <file>
```

License activation.

## File System

```
pwd
cd <directory>
dir
mkdir <directory>
rm <file>
```

File system operations.

## Reset

```
reset saved-configuration
reboot
```

Factory reset and reload.

## H3C System Commands Reference

| Cisco | H3C |
|-------|-----|
| `hostname <name>` | `sysname <name>` |
| `ip domain-name` | `ip domain-name` |
| `username X privilege 15 secret Y` | `aaa` + `local-user X password cipher Y` |
| `line vty` | `user-interface vty` |
| `ntp server` | `ntp-server` |
| `logging host` | `info-center loghost` |
| `show version` | `display version` |
| `show users` | `display users` |
| `erase startup-config` | `reset saved-configuration` |
| `reload` | `reboot` |