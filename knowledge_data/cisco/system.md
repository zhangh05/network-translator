# Cisco System Configuration

## Hostname

```
hostname <name>
```

Set device hostname.

## Domain and DNS

```
ip domain-name <domain>
ip domain-lookup
ip name-server <dns_server>
```

DNS configuration.

## Local Users

```
username <name> privilege <0-15> secret <password>
username <name> privilege 15 algorithm-type scrypt secret <password>
```

Local user database.

## Line VTY

```
line vty 0 4
 login local
 transport input ssh telnet
```

VTY access configuration.

## Time and NTP

```
ntp server <ip>
ntp peer <ip>
clock timezone <zone> <hours>
clock summer-time <zone> recurring
```

Time synchronization.

## Logging

```
logging host <ip>
logging trap <level>
logging source-interface <interface>
service timestamps debug datetime msec
service timestamps log datetime msec
```

Centralized logging.

## Boot System

```
boot system <flash:/filename>
boot system usb:
```

Specify boot image.

## Memory and Processes

```
show memory
show processes cpu
show processes memory
```

System resource monitoring.

## Reset

```
write erase
reload
```

Factory reset.

## Cisco System Commands Reference

| Cisco | Huawei |
|-------|--------|
| `hostname <name>` | `sysname <name>` |
| `ip domain-name` | `ip domain-name` |
| `username X privilege 15 secret Y` | `aaa` + `local-user X password cipher Y` |
| `line vty` | `user-interface vty` |
| `ntp server` | `ntp-server` |
| `logging host` | `info-center loghost` |
| `show version` | `display version` |
| `show users` | `display users` |
| `write erase` | `reset saved-configuration` |
| `reload` | `reboot` |