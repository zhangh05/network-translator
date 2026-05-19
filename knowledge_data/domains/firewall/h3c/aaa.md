# H3C AAA Configuration (Firewall Domain)

## Local Authentication
```
local-user <name> class manage
 password hash <hash>
 authorization-attribute user-role network-admin
 service-type ssh telnet terminal
```

## RADIUS
```
radius scheme <name>
 primary authentication <ip>
 primary accounting <ip>
 key authentication cipher <key>
 key accounting cipher <key>
 user-name-format without-domain
 domain <name>
 authentication default radius-scheme <name>
 authorization default radius-scheme <name>
 accounting default radius-scheme <name>
```
