# Cisco NTP Configuration (Firewall Domain)

## Basic NTP
```
ntp server <ip> prefer
ntp server <ip>
ntp peer <ip>
ntp source <interface-name>
clock timezone <tz> <offset>
ntp update-calendar
```

## NTP Authentication
```
ntp authenticate
ntp authentication-key <id> md5 <key>
ntp trusted-key <id>
ntp server <ip> key <id>
```

## NTP Access Control
```
access-list <num> permit <network> <wildcard>
ntp access-group peer <acl>
ntp access-group serve <acl>
```
