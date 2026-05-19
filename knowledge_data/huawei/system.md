# Huawei System Configuration

## Hostname

```
sysname <hostname>
```

Set device hostname.

## System DNS

```
ip domain-name <domain>
ip domain-lookup
```

DNS settings for name resolution.

## AAA Configuration

```
aaa
 local-user <name> password cipher <pwd>
 local-user <name> privilege level 15
 local-user <name> service-type telnet ssh http
```

Local user accounts.

## Timezone and NTP

```
clock timezone <zone> <offset>
clock datetime <hh:mm:ss> <YYYY-MM-DD>
ntp-server <ip>
ntp-client
```

Time synchronization.

## Log Configuration

```
info-center loghost <ip>
info-center timestamp debug date
info-center timestamp log date
info-center source <source> channel <channel>
```

Centralized logging.

## License

```
license
 active <file> slot <slot>
```

License activation.

## File System

```
pwd
cd <dir>
dir
mkdir <dir>
rm <file>
```

File system operations.

## Reset

```
reset saved-configuration
reboot
```

Factory reset and reload.

## Huawei System Commands Reference

| Cisco | Huawei |
|-------|--------|
| `hostname <name>` | `sysname <name>` |
| `ip domain-name` | `ip domain-name` |
| `username X privilege 15 secret Y` | `aaa` + `local-user X password cipher Y` |
| `ntp server <ip>` | `ntp-server <ip>` |
| `logging host <ip>` | `info-center loghost <ip>` |
| `show version` | `display version` |
| `show users` | `display users` |
| `erase startup-config` | `reset saved-configuration` |
| `reload` | `reboot` |