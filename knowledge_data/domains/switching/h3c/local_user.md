# H3C Local User Configuration

## Local User Account
```
local-user <name> class manage
 password hash <hash>
 authorization-attribute user-role network-admin
 authorization-attribute user-role level-<id>
 service-type ssh telnet terminal
```

## Local User Attributes
```
local-user <name> class manage
 authorization-attribute user-role network-operator
 authorization-attribute acl <acl-num>
 authorization-attribute idle-cut <minutes>
 state active
```
