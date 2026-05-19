# Cisco LLDP Configuration

## Enable LLDP

```
lldp run
lldp holdtime <seconds>
lldp reinit <seconds>
lldp timer <seconds>
```

- `lldp run` — enable LLDP globally
- `holdtime` — time before discarding info
- `reinit` — delay before reinitialization
- `timer` — update interval

## LLDP on Interface

```
interface <interface>
 lldp transmit
 lldp receive
 lldp tlv-select <tlv>
```

- `transmit` — enable sending
- `receive` — enable receiving
- `tlv-select` — select specific TLVs

## LLDP TLV Options

```
lldp tlv-select port-description
lldp tlv-select system-name
lldp tlv-select system-description
lldp tlv-select capabilities
lldp tlv-select management-address
```

Available TLVs to advertise.

## LLDP-MED

```
lldp med transmissions
interface <interface>
 lldp med network-policy <policy_id>
```

Media endpoint discovery extension.

## Display LLDP

```
show lldp
show lldp neighbors
show lldp neighbors detail
show lldp interface
```

## Cisco LLDP Commands Reference

| Cisco | Huawei |
|-------|--------|
| `lldp run` | `lldp enable` |
| `lldp transmit` | `lldp tx` |
| `lldp receive` | `lldp rx` |
| `lldp holdtime` | `lldp message-rate` |
| `lldp timer` | `lldp timer` |
| `lldp reinit` | `lldp tx-delay` |
| `show lldp neighbors` | `display lldp neighbor` |
| `show lldp interface` | `display lldp local` |