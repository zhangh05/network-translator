# H3C SSH Configuration (Switching Domain)

## SSH Server
```
public-key local create rsa
ssh server enable
ssh server port <port>
ssh server authentication-retries <num>
ssh server timeout <minutes>
line vty 0 63
 authentication-mode scheme
 protocol inbound ssh
user-role network-admin
```
