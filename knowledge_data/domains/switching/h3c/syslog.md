# H3C Syslog/Log Configuration (Switching Domain)

## Logging to Remote Server
```
info-center enable
info-center loghost <ip>
info-center loghost <ip> port <port>
info-center loghost <ip> facility <level>
info-center timestamp log {date | short | millisecond}
```

## Log Output
```
info-center console channel <id>
info-center monitor channel <id>
info-center logbuffer size <size>
```
