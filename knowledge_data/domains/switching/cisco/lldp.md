# Cisco LLDP Configuration (Switching Domain)

## Global LLDP
```
lldp run
lldp timer <seconds>
lldp holdtime <seconds>
lldp reinit <seconds>
lldp tlv-select <tlv-type>
```

## Interface LLDP
```
interface <interface>
 lldp transmit
 lldp receive
 lldp tlv-enable <tlv-type>
 no lldp transmit
 no lldp receive
```
