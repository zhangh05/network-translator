# H3C SNMP Configuration (Switching Domain)

## SNMPv2c
```
snmp-agent
snmp-agent community read <string>
snmp-agent community write <string>
snmp-agent sys-info location <text>
snmp-agent sys-info contact <text>
snmp-agent trap enable
snmp-agent target-host trap address udp-domain <ip> params securityname <community>
snmp-agent target-host trap address udp-domain <ip> params securityname <community_v3> v3
```

## SNMPv3
```
snmp-agent sys-info version v3
snmp-agent group v3 <group> privacy
snmp-agent usm-user v3 <user> <group> simple authentication-mode sha <key> privacy-mode aes128 <key>
snmp-agent target-host trap address udp-domain <ip> params securityname <user> v3 privacy
```
