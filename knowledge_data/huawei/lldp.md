# Huawei LLDP Configuration

## Enable LLDP

```
lldp enable
lldp message-rate <rate>
```

- `lldp enable` — enable LLDP globally (default on Huawei)
- `lldp message-rate` — control LLDP packet rate

## LLDP on Interface

```
interface <interface>
 lldp enable
 lldp tx-delay <seconds>
 lldp rx
 lldp tx
```

- `lldp tx` / `lldp rx` — enable transmit/receive
- `lldp tx-delay` — delay between transmissions

## Management Address

```
lldp management-address <ip>
```

Set the management address to advertise.

## LLDP TLV Select

```
lldp tlv-enable basic-tlv port-description
lldp tlv-enable basic-tlv system-name
lldp tlv-enable basic-tlv system-description
lldp tlv-enable dot1-tlv vlan-name
```

Select which TLVs to advertise.

## Display LLDP

```
display lldp neighbor
display lldp local
display lldp statistics
```

## Huawei LLDP Commands Reference

| Cisco | Huawei |
|-------|--------|
| `lldp run` | `lldp enable` |
| `lldp transmit` | `lldp tx` |
| `lldp receive` | `lldp rx` |
| `lldp holdtime <sec>` | `lldp message-rate` |
| `lldp reinit` | `lldp tx-delay` |
| `show lldp neighbors` | `display lldp neighbor` |
| `show lldp interface` | `display lldp local` |