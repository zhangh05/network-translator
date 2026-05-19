# Huawei NTP Configuration (Switching Domain)

## Basic NTP
```
ntp-service unicast-server <ip>
ntp-service unicast-server <ip> prefer
ntp-service unicast-peer <ip>
ntp-service source-interface <interface>
clock timezone <tz> add <offset>
```

## NTP Authentication
```
ntp-service authentication enable
ntp-service authentication-keyid <id> authentication-mode md5 <key>
ntp-service reliable authentication-keyid <id>
ntp-service unicast-server <ip> authentication-keyid <id>
```
