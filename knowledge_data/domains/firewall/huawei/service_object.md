# Huawei USG Service Object → Cisco ASA Mapping

## Source Syntax (Huawei USG)
- `ip service-set <NAME> type object` — Defines a named service group
- `service <N> protocol <PROTO> source-port <SP> destination-port <DP>` — Service definition
- `ip service-set <NAME> type group` — Defines a group of service-sets (nested groups)

## Target Syntax (Cisco ASA)
- `object-group service <NAME>` — Defines a named service object group
- `service-object <PROTO> [source] destination eq <PORT>` — Service entry within object-group
- `service-object tcp destination eq <PORT>` — TCP service
- `group-object <NAME>` — Reference to another object-group (nesting)

## Translation Rules
1. `ip service-set <NAME> type object` → `object-group service <NAME> tcp` (or `udp` if uniform)
2. Each `service <N> protocol tcp destination-port <DP>` → `service-object tcp destination eq <DP>`
3. Each `service <N> protocol udp destination-port <DP>` → `service-object udp destination eq <DP>`
4. For mixed protocol service-sets, use `object-group service <NAME>` without protocol constraint, then individual `service-object` lines
5. Do NOT use `object service <NAME>` for service-set — `object service` has different semantics on ASA

## Key Distinction
- Cisco ASA has TWO service object types:
  - `object service <NAME>` — Single service definition, used in object NAT
  - `object-group service <NAME>` — Multiple service entries, used in ACLs
- Huawei `ip service-set` is a GROUP (multiple ports/protocols) → must use `object-group service`, NOT `object service`
- When security-policy references a service-set by name, the ACL must reference the corresponding object-group by name
