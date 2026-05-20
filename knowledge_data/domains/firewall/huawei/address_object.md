# Huawei USG Address Object → Cisco ASA Mapping

## Source Syntax (Huawei USG)
- `ip address-set <NAME> type object` — Defines a named address group (multiple addresses)
- `address <N> <IP> <MASK>` — Individual address entry within address-set (N = 0-indexed)
- `ip address-set <NAME> type group` — Defines a group of address-sets (nested groups)

## Target Syntax (Cisco ASA)
- `object-group network <NAME>` — Defines a named network object group (multiple subnets/hosts)
- `network-object <IP> <MASK>` — Individual network/subnet entry within object-group
- `host <IP>` — Individual host entry within object-group
- `group-object <NAME>` — Reference to another object-group (nesting)

## Translation Rules
1. `ip address-set <NAME> type object` → `object-group network <NAME>`
2. Each `address <N> <IP> <MASK>` → `network-object <IP> <MASK>`
3. `ip address-set <NAME> type group` → `object-group network <NAME>` with `group-object` entries
4. Do NOT use `object network <NAME>` for address-set — `object network` is for a SINGLE host/subnet, not a group

## Key Distinction
- Cisco ASA has TWO object types:
  - `object network <NAME>` — Contains exactly ONE host/subnet/range. Used in NAT.
  - `object-group network <NAME>` — Contains MULTIPLE network-object/group-object entries. Used in ACLs.
- Huawei `ip address-set` is a GROUP (multiple addresses) → must use `object-group network`, NOT `object network`
- When security-policy references an address-set, the ACL must reference the corresponding object-group
