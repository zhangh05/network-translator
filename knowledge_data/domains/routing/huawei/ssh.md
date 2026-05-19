# Huawei SSH Configuration (Routing Domain)

## SSH Server
```
rsa local-key-pair create
stelnet server enable
ssh server port <port>
ssh server authentication-retries <num>
ssh server timeout <minutes>
user-interface vty 0 4
 authentication-mode aaa
 protocol inbound ssh
```
