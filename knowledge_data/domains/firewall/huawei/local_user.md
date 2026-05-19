# Huawei Local User Configuration

## Local User Account
```
aaa
 local-user <name> password irreversible-cipher <password>
 local-user <name> privilege level <level>
 local-user <name> service-type terminal telnet ssh
 local-user <name> state active
 quit
```

## Local User Authorization
```
aaa
 local-user <name> authorization-attribute user-role <role>
 local-user <name> authorization-attribute acl <acl-num>
 local-user <name> idle-timeout <minutes>
```
