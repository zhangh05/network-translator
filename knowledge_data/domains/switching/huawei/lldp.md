# Huawei LLDP Configuration (Switching Domain)

## Global LLDP
```
lldp enable
lldp message-transmission interval <seconds>
lldp message-transmission hold-multiplier <num>
lldp reinit-delay <seconds>
lldp tlv-enable <tlv-type>
```

## Interface LLDP
```
interface <interface>
 lldp enable
 lldp transmit
 lldp receive
 undo lldp enable
```
