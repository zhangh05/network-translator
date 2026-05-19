# Cisco Syslog/Log Configuration (Firewall Domain)

## Logging to Remote Server
```
logging host <ip>
logging host <ip> transport udp <port>
logging host <ip> transport tcp <port>
! Set logging severity (0-7)
logging trap <level>
logging source-interface <interface>
logging on
logging buffered <size>
logging console <level>
logging monitor <level>
```

## Timestamp
```
service timestamps log datetime msec localtime show-timezone
service timestamps debug datetime msec localtime show-timezone
```
