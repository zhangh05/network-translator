# H3C LLDP Configuration

## Enable LLDP

```
lldp enable
lldp interval <seconds>
```

- `lldp enable` — enable globally (default on H3C)
- `interval` — advertisement interval

## LLDP on Interface

```
interface <interface>
 lldp enable
 lldp admin-status <tx|rx|txrx>
```

- `admin-status tx` — transmit only
- `admin-status rx` — receive only
- `admin-status txrx` — both

## Management Address TLV

```
lldp management-address <ip>
```

Advertise specific management address.

## LLDP TLV Selection

```
lldp tlv-format basic-tlv port-description
lldp tlv-format basic-tlv system-name
lldp tlv-format dot1-tlv vlan-name
```

Select TLVs to include.

## LLDP-MED

```
lldp fast-count <count>
lldp tlv-format med-tlv network-policy
```

Media Endpoint Discovery.

## Display LLDP

```
display lldp neighbor
display lldp local
display lldp statistics
```

## H3C LLDP Commands Reference

| Cisco | H3C |
|-------|-----|
| `lldp run` | `lldp enable` |
| `lldp transmit` | `admin-status tx` |
| `lldp receive` | `admin-status rx` |
| `lldp holdtime` | `lldp interval` (indirect) |
| `lldp reinit` | `lldp fast-count` |
| `show lldp neighbors` | `display lldp neighbor` |
| `show lldp interface` | `display lldp local` |