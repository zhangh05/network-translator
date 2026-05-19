# Cisco Local User Configuration

## Local User Account
```
username <name> privilege <level> secret <password>
username <name> privilege 15 secret <password>
username <name> secret <password>
```

## Local User with SSH Key
```
ip ssh pubkey-chain
 username <name>
  key-hash ssh-rsa <hash>
```

## Local User Attributes
```
username <name> privilege <level>
username <name> view <view-name>
username <name> autocommand <command>
```

## Enable Password
```
enable secret <password>
enable password <password>
enable algorithm-type scrypt secret <password>
```
