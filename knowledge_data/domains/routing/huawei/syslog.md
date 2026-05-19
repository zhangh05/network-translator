# Huawei Syslog/Log Configuration (Routing Domain)

## Logging to Remote Server
```
info-center enable
info-center loghost <ip>
info-center loghost <ip> channel <id> facility <level>
info-center loghost <ip> transport tcp
info-center source default channel loghost log level informational
info-center timestamp log {date | short | millisecond}
```

## Log Output
```
info-center console channel <id>
info-center monitor channel <id>
info-center logbuffer size <size>
info-center logbuffer channel <id>
```
