# Cisco AAA Configuration (Firewall Domain)

## Local Authentication
```
username <name> privilege <level> secret <password>
aaa new-model
aaa authentication login default local
aaa authorization exec default local
```

## TACACS+
```
tacacs-server host <ip> key <key>
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa accounting exec default start-stop group tacacs+
```

## RADIUS
```
radius-server host <ip> key <key>
aaa authentication login default group radius local
aaa authorization exec default group radius local
aaa accounting exec default start-stop group radius
```
