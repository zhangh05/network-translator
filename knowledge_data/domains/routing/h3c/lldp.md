# H3C LLDP Configuration (Routing Domain)

## Global LLDP
```
lldp global enable
lldp timer tx-interval <seconds>
lldp timer hold-multiplier <num>
lldp timer reinit-delay <seconds>
```

## Interface LLDP
```
interface <interface>
 lldp enable
```
