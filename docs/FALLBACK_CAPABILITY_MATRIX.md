# Fallback Capability Matrix

> **Disclaimer**: The deterministic fallback is a **conservative, line-by-line** translation layer for high-frequency primitives only. It outputs `# MANUAL_REVIEW` for any unrecognized construct. The **main translation pipeline** remains **Parser → IR → Renderer → Validator** (structural/LLM-driven). The fallback exists solely as a safety net when the main pipeline is unavailable or produces no output. Complex scenarios (deep BGP policy, IPSec VPN, multi-vendor QoS, inter-VRF route leaking) always require the structural translation pipeline.

## Vendor Platform Identifiers

| ID | Vendor | Domains |
|----|--------|---------|
| `cisco_ios_xe` | Cisco IOS-XE | SWITCH, ROUTER |
| `h3c_comware` | H3C Comware | SWITCH, ROUTER |
| `huawei_vrp` | Huawei VRP | SWITCH, ROUTER |
| `huawei_usg` | Huawei USG | FIREWALL |
| `ruijie_rgos` | Ruijie RGOS | SWITCH, ROUTER |
| `hillstone_stoneos` | Hillstone StoneOS | FIREWALL |
| `topsec_tos` | Topsec TOS | FIREWALL |
| `dptech_fw` | DPtech firewall | FIREWALL |

## MANAGEMENT Plane

Source file: `core/fallback/management_rules.py`
Test file: `tests/test_rule_translator_management.py`

### hostname / sysname — bidirectional

| Source | Target Cisco | Target Huawei / H3C | Target Ruijie |
|--------|-------------|---------------------|--------------|
| `hostname NAME` | passthrough | `sysname NAME` | `hostname NAME` |
| `sysname NAME` | `hostname NAME` | passthrough | `hostname NAME` |

### NTP

| Source | Target Huawei | Target Cisco | Target H3C | Target Ruijie |
|--------|--------------|-------------|------------|--------------|
| `ntp server A.B.C.D` | `ntp-service unicast-server A.B.C.D` | `ntp server A.B.C.D` | `ntp server A.B.C.D` | `ntp server A.B.C.D` |
| `ntp source-interface IF` | `ntp-service source-interface IF_norm` | `ntp source-interface IF_norm` | `ntp source IF_norm` | `ntp source IF_norm` |
| `ntp server vrf VRF ADDR` | MANUAL_REVIEW (vrf not portable) | MANUAL_REVIEW | MANUAL_REVIEW | MANUAL_REVIEW |
| `ntp-service unicast-server ADDR` | passthrough | `ntp server ADDR` | `ntp server ADDR` | `ntp server ADDR` |
| `ntp-service source-interface IF` | passthrough | `ntp source-interface IF_norm` | `ntp source IF_norm` | `ntp source IF_norm` |

### Logging / info-center

| Source | Target Huawei | Target Cisco | Target H3C | Target Ruijie |
|--------|--------------|-------------|------------|--------------|
| `logging host A.B.C.D` | `info-center loghost A.B.C.D` | passthrough | `logging A.B.C.D` | `logging A.B.C.D` |
| `logging source-interface IF` | `info-center source IF_norm` | `logging source-interface IF_norm` | MANUAL_REVIEW | MANUAL_REVIEW |
| `info-center loghost A.B.C.D` | passthrough | `logging host A.B.C.D` | `logging A.B.C.D` | `logging A.B.C.D` |
| `info-center source IF` | passthrough | `logging source-interface IF_norm` | MANUAL_REVIEW | MANUAL_REVIEW |

> **Note**: facility/severity/channel semantics differ across vendors. Unrecognized combinations → MANUAL_REVIEW. Do not assume equivalence without explicit mapping.

### SNMP

| Source | Target | Behavior |
|--------|--------|----------|
| `snmp-server enable traps` | all vendors | Auto-translate |
| `snmp-agent trap enable` | all vendors | Auto-translate |
| `snmp-agent community NAME <cipher/plain>` | all vendors | Always `<redacted>` + MANUAL_REVIEW |
| `snmp-agent target-host ... v3` | all vendors | MANUAL_REVIEW (v3 not portable) |
| `snmp-server trap-source IF` | all except Cisco | `snmp-agent trap source IF_norm` |
| `snmp-server host ... community NAME` | all | `<redacted>` + MANUAL_REVIEW |

### AAA / passwords — ALWAYS MANUAL_REVIEW or <redacted>

| Command pattern | Behavior |
|-----------------|----------|
| `password * VALUE` | Always `<redacted>` + MANUAL_REVIEW, never output as executable |
| `secret * VALUE` | Always `<redacted>` + MANUAL_REVIEW |
| `irreversible-cipher * VALUE` | Always `<redacted>` + MANUAL_REVIEW |
| `cipher * VALUE` | Always `<redacted>` + MANUAL_REVIEW |
| `simple-text * VALUE` | Always `<redacted>` + MANUAL_REVIEW |
| `community STRING` (SNMP) | Always `<redacted>` + MANUAL_REVIEW |
| `local-user NAME ... password` | Always `<redacted>` + MANUAL_REVIEW |
| `username NAME password ...` | Always `<redacted>` + MANUAL_REVIEW |
| `radius shared-key ...` | Always `<redacted>` + MANUAL_REVIEW |
| `aaa authentication/login` header | MANUAL_REVIEW (auth policy not portable without explicit mapping) |
| `aaa authorization` | MANUAL_REVIEW |
| `aaa accounting` | MANUAL_REVIEW |

**Principle**: No password, secret, key, or credential value may appear in `deployable_config` as plain text. All must be `<redacted>`.

## ACL / QoS Plane

Source files: `core/fallback/acl_rules.py`, `core/fallback/switch_rules.py`
Test file: `tests/test_rule_translator_acl_binding.py`

### Auto-translate: ACL headers

| Source | Target | Feature |
|--------|--------|---------|
| `ip access-list extended NAME` (Cisco) | Huawei/H3C/Ruijie | ACL container → `acl name NAME advanced` |
| `ip access-list standard NAME` (Cisco) | Huawei/H3C/Ruijie | ACL container → `acl name NAME basic` |
| `acl number N` header (Huawei) | Cisco | ACL → named/numbered Cisco ACL |
| Named Huawei ACL (`acl name NAME`) | Cisco | ACL container passthrough or MANUAL_REVIEW |

### Auto-translate: ACL rules (basic)

| Source | Target | Conditions |
|--------|--------|------------|
| `rule N permit ip source S D` | all | Auto |
| `rule N deny ip source S D` | all | Auto |
| `rule N permit tcp source S D destination Dst dst-port eq PORT` | all | Auto (simple eq only) |
| `rule N permit icmp source S D` | all | Auto |
| `rule N permit udp source S D destination Dst` | all | Auto |
| `access-list N permit ip S D` (Cisco) | Huawei/H3C | Auto |
| `access-list N permit tcp S D Dst dst-port eq PORT` | Huawei/H3C | Auto |
| `ip access-group NAME in` / `out` | Huawei | `traffic-filter inbound acl NAME` / `outbound acl NAME` |
| `ip access-group NAME in` / `out` | H3C | `packet-filter NAME inbound` / `outbound` |
| `traffic-filter inbound acl NAME` (Huawei) | H3C | `packet-filter NAME inbound` |
| `traffic-filter outbound acl NAME` (Huawei) | H3C | `packet-filter NAME outbound` |
| `packet-filter NUM inbound` / `outbound` (H3C) | Huawei | `traffic-filter inbound acl NUM` / `outbound acl NUM` |

### MANUAL_REVIEW: ACL rules

The following must NOT be auto-translated (semantic risk too high):

| Pattern | Reason |
|---------|--------|
| `rule ... object-group`, `object`, `evaluate`, `reflect`, `dynamic` | Advanced ACL objects not mappable across vendors |
| `rule ... source-port`, `destination-port gt/lt/neq/range` | Port operators beyond `eq` differ across vendors |
| `rule ... vpn-instance` | VRF awareness not portable without explicit mapping |
| `rule ... time-range` | Time-range schedules are vendor-specific |
| `rule ... logging` / `enable` flags | Audit/logging semantics differ |
| `traffic-policy / service-policy` body (QoS actions: `car`, `remark dscp`, `queue`) | QoS policy bodies always MANUAL_REVIEW |
| Cisco `access-list N remark` | Remarks can be passed through as comments |

### QoS — Interface binding only (safe subset)

| Source | Target | Conditions |
|--------|--------|------------|
| `traffic-policy P inbound` (Huawei/H3C) | Cisco | `service-policy input P` (QoS body remains MANUAL_REVIEW) |
| `traffic-policy P outbound` (Huawei/H3C) | Cisco | `service-policy output P` (QoS body remains MANUAL_REVIEW) |

**Everything inside `traffic-policy / traffic-classifier / traffic-behavior / car / remark dscp / queue`** → MANUAL_REVIEW.

## SWITCH Domain

Test file: `tests/test_rule_translator_switch_multivendor.py`

### Auto-translate

| Feature | Details |
|---------|---------|
| hostname / sysname | Bidirectional between all 4 vendors |
| VLAN single | Passthrough for all vendors |
| VLAN range (comma-separated / batch / to) | Cisco `10,20` ↔ Huawei `batch 10 to 20` ↔ H3C `10 to 20` ↔ Ruijie `10,20` |
| Interface name normalization | Speed/LAG/SVI across all pairs |
| switchport mode trunk / access | All directional pairs |
| switchport trunk allowed vlan / port trunk permit / allow-pass | All directional pairs |
| switchport access vlan / port default vlan | All directional pairs |
| LAG member binding | channel-group / eth-trunk / bridge-aggregation / port-group ↔ cross-vendor equivalent |
| STP portfast / stp edged-port | Cisco ↔ Huawei ↔ H3C ↔ Ruijie |
| description / ip address / shutdown / no shutdown | All vendors |

### MANUAL_REVIEW

| Feature | All Directions |
|---------|---------------|
| spanning-tree bpduguard | MANUAL_REVIEW for all cross-vendor |
| spanning-tree loopguard | MANUAL_REVIEW for all cross-vendor |
| spanning-tree guard root | MANUAL_REVIEW for all cross-vendor |
| Unknown spanning-tree sub-commands | MANUAL_REVIEW for all cross-vendor |
| route-map / route-policy / prefix-list | MANUAL_REVIEW for all cross-vendor |

### Not Supported

- Deep STP configuration (bridge priority, VLAN-to-instance mapping, MST regions)
- Private VLANs (PVLAN / community VLAN)
- LLDP / CDP mapping
- QoS / traffic policy mapping across vendors

## ROUTER Domain

Test file: `tests/test_rule_translator_router_multivendor.py`

**Important**: OSPF, BGP, and VRF commands in the fallback are **basic header-to-header and neighbor-to-peer translations only**. They do NOT perform semantic validation. Deep routing protocol validation requires the structural pipeline and semantic comparison.

### Auto-translate

| Feature | Details |
|---------|---------|
| Static route (`ip route` ↔ `ip route-static`) | All directional pairs, with route options flagged as MANUAL_REVIEW |
| OSPF process header | `router ospf N` ↔ `ospf N` (all pairs) |
| OSPF router-id | Passthrough |
| OSPF area / network | Passthrough |
| OSPF passive-interface / silent-interface | `passive-interface` ↔ `silent-interface` / `undo silent-interface` ↔ `no passive-interface` |
| BGP process header | `router bgp ASN` ↔ `bgp ASN` (all pairs) |
| BGP neighbor remote-as / peer as-number | All directional pairs |
| BGP network mask | Passthrough |
| VRF definition / ip vpn-instance | All directional pairs |
| route-distinguisher / rd | All directional pairs |
| vpn-target / route-target | All directional pairs |

### MANUAL_REVIEW

| Feature | All Directions |
|---------|---------------|
| Static route options (preference, tag, track, bfd) | MANUAL_REVIEW |
| OSPF area type (nssa, stub, virtual-link) | MANUAL_REVIEW |
| BGP neighbor sub-commands (description, update-source, password) | MANUAL_REVIEW |
| route-map / route-policy / prefix-list body commands | MANUAL_REVIEW |

### Not Supported

- Inter-VRF route leaking
- BGP community / large-community / ext-community
- MPLS / LDP / segment routing
- Route redistribution between protocols
- BGP route reflection and confederation
- OSPF interface cost / hello/dead interval tuning

## FIREWALL Domain

Test file: `tests/test_rule_translator_firewall.py`, `tests/test_rule_translator_firewall_objects.py`

### Auto-translate

| Source | Target | Feature | Conditions |
|--------|--------|---------|------------|
| Huawei USG | Hillstone | Zone / address / service / policy | Complete multi-line security-policy block |
| Hillstone | Huawei USG | Zone / address / service / policy | Complete flat policy with all required fields |
| Topsec | Huawei USG | Zone | `zone name <zone>` |
| Topsec | Huawei USG | Address object | `address name NAME ip A.B.C.D mask MMM.MMM.MMM.MMM` → `ip address-set NAME type object` + `address 0 A.B.C.D mask MMM.MMM.MMM.MMM` |
| Topsec | Huawei USG | Policy | Only when **all 6 fields present**: source-zone, destination-zone, source-address, destination-address, service, action. Output: `security-policy` + `rule name ...` block |
| Hillstone | Topsec | Zone | `zone <zone>` → `zone name <zone>` |
| Hillstone | Topsec | Address object | `address NAME IP MASK` / `address NAME IP host` → `address name NAME ip IP mask MASK` |
| Hillstone | Topsec | Policy | Only when **all required fields present**: from, to, source, destination, service, action. Output: Topsec `policy name ...` format |
| DPtech | Huawei USG | Zone / address / policy | Complete policy with all required fields |
| DPtech | Hillstone | Zone / policy | Complete policy with all required fields |
| Topsec | Topsec | Passthrough | Same-vendor; non-dangerous commands pass through unchanged |

### Firewall policy fields — NO implicit defaults

All firewall policy translations require explicit fields. **Implicit "any" is not permitted.**

Required fields per direction:

| Direction | Required Fields |
|-----------|-----------------|
| Topsec → Huawei USG | `source-zone`, `destination-zone`, `source-address`, `destination-address`, `service`, `action` |
| Hillstone → Topsec | `from`, `to`, `source`, `destination`, `service`, `action` |
| DPtech → Huawei USG / Hillstone | `source-zone`, `destination-zone`, `source-address`, `destination-address`, `service`, `action` |

**Missing any required field → MANUAL_REVIEW**. Output must not contain an executable policy block if fields are missing.

### MANUAL_REVIEW

| Source | Target | MANUAL_REVIEW Items |
|--------|--------|---------------------|
| Huawei USG | Hillstone | Zone add interface, address-set range, service-set source-port, multi-value fields, time-range, log, session, user, application, profile sub-commands |
| Hillstone | Huawei USG | NAT, IPSec, VPN, URL filter, AV, time-range, log, session, profile, application, user |
| Topsec | Huawei USG | Address range/special types, service objects, policy with missing fields |
| Topsec | Hillstone | Address range/special types, service objects, policy with missing fields |
| Hillstone | Topsec | Service objects (if not implementable as flat service) |
| DPtech | Huawei USG / Hillstone | NAT, IPSec, VPN, URL filter, AV, address range (`start...end`), policy with missing source-address |
| Topsec | Topsec | Dangerous features (see below) |
| All → Topsec (non-Topsec/Hillstone source) | Any non-Topsec/Hillstone source to Topsec | All features — Topsec-specific commands required; Huawei USG/DPtech/cisco/huawei/h3c commands cannot be auto-translated to Topsec |
| All → Topsec | Zone add interface / bind interface | Interface binding to zone always requires manual review |
| All → Hillstone | Zone add interface | Interface binding not portable |
| All → Huawei USG | Zone add interface | Interface binding not portable |

### Dangerous features — always MANUAL_REVIEW (all directions)

`nat`, `source-nat`, `destination-nat`, `ipsec`, `ike`, `vpn`, `tunnel`, `url-filter`, `antivirus`, `av-profile`, `intrusion`, `ips`, `time-range`, `log`, `session`, `profile`, `application`, `user`

### Not Supported

- Firewall policy order merging (outputs line-by-line, first-match semantics not reordered)
- NAT / PAT equivalence across vendors
- IPSec / VPN tunnel parameter mapping
- Deep policy inspection rules
- User/group-based access rules

## Test Coverage Summary

| File | Scope |
|------|-------|
| `tests/test_rule_translator.py` | SWITCH + ROUTER + FIREWALL — 19 tests |
| `tests/test_rule_translator_firewall.py` | FIREWALL (Hillstone ↔ Huawei USG ↔ Topsec ↔ DPtech) — 28 tests |
| `tests/test_rule_translator_firewall_objects.py` | Firewall object/policy details — 84 tests |
| `tests/test_safe_fallback_and_block_splitter.py` | Infrastructure (safe fallback guard, splitter) |
| `tests/test_rule_translator_switch_multivendor.py` | SWITCH (12 direction pairs + negatives) |
| `tests/test_rule_translator_router_multivendor.py` | ROUTER (static/OSPF/BGP/VRF multi-direction) |
| `tests/test_rule_translator_management.py` | MANAGEMENT (NTP/logging/SNMP/AAA/hostname) — 79 tests |
| `tests/test_rule_translator_acl_binding.py` | ACL and interface binding — 59 tests |
| `tests/test_realistic_fallback_report.py` | Fallback report structure and redaction — 27 tests |
| `tests/test_rule_translator_realistic_samples.py` | 6 end-to-end realistic samples |
| `tests/test_fallback_capability_matrix.py` | Capability matrix — 13 tests |
| `tests/test_rule_translator_realistic_batch_i_e.py` | Realistic medium-length configs (4 directions) — 21 tests |

## Version History

| Date | Change |
|------|--------|
| 2026-05-24 | Initial matrix — covers Batch A-D fallback enhancements |
| 2026-05-24 Batch I | Added MANAGEMENT section, ACL/QoS section, updated firewall source-path table, clarified AAA/password rules and no-implicit-any policy |
| 2026-05-24 Batch I-B | MANAGEMENT: NTP source-interface (H3C/Ruijie), logging facility/manual_review, radius/tacacs key redaction, 37 new tests (79 total) |
| 2026-05-24 Batch I-C | ACL/QoS: H3C→Huawei packet-filter, Cisco named ACL header, Huawei ACL rule→Cisco, object-group/manual_review guards, 32 new tests (59 total) |
| 2026-05-25 Batch I-D | FIREWALL: Topsec→Huawei USG (zone/address/policy), Hillstone→Topsec (zone/address/policy), DPtech completeness, dangerous feature guards, address mask netmask format, Topsec routing fix (non-Topsec/Hillstone sources to Topsec → MANUAL_REVIEW), 84 firewall tests |
| 2026-05-25 Batch I-E | Realistic samples: Cisco→Huawei trunk/access/SVI/ACL/OSPF/NTP/AAA, Huawei→Cisco Vlanif/ACL/OSPF/SNMP/AAA, Topsec→Huawei USG complete policy, Hillstone→Topsec complete policy. Fix: no switchport (Cisco routed-port) dropped in Huawei output, BGP neighbor password redacted in MANUAL_REVIEW. New test file: 21 realistic tests |