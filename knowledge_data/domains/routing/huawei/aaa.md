# Huawei AAA Configuration (Routing Domain)

## Local Authentication
```
aaa
 local-user <name> password irreversible-cipher <password>
 local-user <name> privilege level <level>
 local-user <name> service-type terminal telnet ssh
 quit
```

## RADIUS
```
radius-server template <name>
 radius-server shared-key-cipher <key>
 radius-server authentication <ip> <port>
 radius-server accounting <ip> <port>
 quit
aaa
 authentication-scheme <name>
  authentication-mode radius
 accounting-scheme <name>
  accounting-mode radius
 domain <name>
  authentication-scheme <name>
  accounting-scheme <name>
  radius-server <name>
```
