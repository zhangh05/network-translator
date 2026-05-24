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

## Interface Name Mapping

The fallback normalizes interface names across all supported vendor pairs.

### Speed / Media Type

| Source | Target Cisco | Target Huawei / H3C |
|--------|-------------|---------------------|
| `GigabitEthernet` | passthrough | passthrough |
| `TenGigabitEthernet` | passthrough | `XGigabitEthernet` |
| `XGigabitEthernet` | `TenGigabitEthernet` | passthrough |
| `FortyGigabitEthernet` | passthrough | passthrough |
| `HundredGigE` | passthrough | passthrough |

### LAG (Link Aggregation)

| Source | Target Cisco | Target Huawei | Target H3C | Target Ruijie |
|--------|-------------|--------------|------------|---------------|
| `Port-channel N` | passthrough | `Eth-Trunk N` | `Bridge-Aggregation N` | `AggregatePort N` |
| `Eth-Trunk N` | `Port-channel N` | passthrough | `Bridge-Aggregation N` | `AggregatePort N` |
| `Bridge-Aggregation N` | `Port-channel N` | `Eth-Trunk N` | passthrough | `AggregatePort N` |
| `AggregatePort N` | `Port-channel N` | `Eth-Trunk N` | `Bridge-Aggregation N` | passthrough |
| `channel-group N` command | passthrough | `eth-trunk N` | `port link-aggregation group N` | `port-group N mode active` |
| `eth-trunk N` command | `channel-group N mode active` | passthrough | `port link-aggregation group N` | `port-group N mode active` |
| `bridge-aggregation N` command | `channel-group N mode active` | `eth-trunk N` | passthrough | `port-group N mode active` |
| `port-group N` command | `channel-group N mode active` | `eth-trunk N` | `port link-aggregation group N` | passthrough |

### SVI (Switched Virtual Interface)

| Source | Target Cisco | Target Huawei | Target H3C | Target Ruijie |
|--------|-------------|--------------|------------|---------------|
| `interface Vlan N` | passthrough | `interface Vlanif N` | `interface Vlan-interface N` | passthrough |
| `interface Vlanif N` | `interface Vlan N` | passthrough | `interface Vlan-interface N` | `interface Vlan N` |
| `interface Vlan-interface N` | `interface Vlan N` | `interface Vlanif N` | passthrough | `interface Vlan N` |

### Loopback / Null

| Source | Target Cisco | Target Huawei | Target H3C | Target Ruijie |
|--------|-------------|--------------|------------|---------------|
| `Loopback N` / `LoopBack N` | `Loopback N` | passthrough | passthrough | `Loopback N` |
| `NULL N` | `Null N` | passthrough | passthrough | `Null N` |
| `MEth N` | `# MANUAL_REVIEW` | passthrough | passthrough | `# MANUAL_REVIEW` |

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
| STP portfast / stp edged-port | Cisco ↔ Huawei (stp edged-port enable) ↔ H3C ↔ Ruijie |
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

**Important**: OSPF, BGP, and VRF commands in the fallback are **basic header-to-header and neighbor-to-peer translations only**. They do NOT perform semantic validation (area matching, ASN consistency check, network statement overlap analysis, route-policy semantics). Deep routing protocol validation requires the structural pipeline and semantic comparison.

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

Test file: `tests/test_rule_translator_firewall.py`, `tests/test_rule_translator.py` (relevant fragments)

### Auto-translate

| Source | Target | Feature |
|--------|--------|---------|
| Huawei USG | Hillstone | Zone definition (`security-zone name Z` → `zone Z`) |
| Huawei USG | Hillstone | Address object (`ip address-set NAME type object` → `address NAME IP MASK`) |
| Huawei USG | Hillstone | Service object (`ip service-set NAME type object` → `service NAME proto PORT`) |
| Huawei USG | Hillstone | Security policy header + multi-line rule (rule name → policy, action/source/destination/service) |
| Hillstone | Huawei USG | Zone definition (`zone Z` → `security-zone name Z`) |
| Hillstone | Huawei USG | Address object (`address NAME IP MASK` → `ip address-set NAME type object`) |
| Hillstone | Huawei USG | Service object (`service NAME proto PORT` → `ip service-set NAME type object`) |
| Hillstone | Huawei USG | Policy → security-policy rule |
| Topsec | Hillstone | Zone / address / policy |
| DPtech | Huawei USG | Zone / address / service |

### MANUAL_REVIEW

| Source Path | MANUAL_REVIEW Items |
|-------------|---------------------|
| Huawei USG → Hillstone | Zone interface binding (`add interface IF`), address-set range (`address N start end`), service-set source-port, multi-value source/destination/service in policy (first value preserved, rest flagged), time-range, log, session, user, application, profile policy sub-commands |
| Hillstone → Huawei USG | NAT, IPSec, ALG blocks |
| Topsec → Hillstone | NAT, IPSec, ALG blocks |
| DPtech → Huawei USG | NAT, IPSec, ALG blocks |
| All → Hillstone | Policy attributes beyond basic source/destination/service/action |

### Not Supported

- Firewall policy order merging (outputs line-by-line, first-match semantics not reordered)
- NAT overload / PAT equivalence across vendors
- IPSec tunnel parameter mapping
- Deep policy inspection rules
- VPN configuration (L2TP, IPsec, SSL VPN)
- User/group-based access rules

## Test Coverage Summary

| File | Domains |
|------|---------|
| `tests/test_rule_translator.py` | SWITCH + ROUTER (static/BGP/OSPF) + FIREWALL (Huawei USG ↔ Hillstone) — covered by 49 unit tests |
| `tests/test_rule_translator_firewall.py` | FIREWALL (Hillstone ↔ Huawei USG ↔ Topsec ↔ DPtech) — covered by unit tests |
| `tests/test_safe_fallback_and_block_splitter.py` | Infrastructure (safe fallback guard, splitter pipe) |
| `tests/test_rule_translator_switch_multivendor.py` | SWITCH (12 direction pairs + 4 negative/manual tests + 3 Batch C tests) |
| `tests/test_rule_translator_router_multivendor.py` | ROUTER (static/OSPF/BGP/VRF multi-direction + 4 Batch C tests) |
| `tests/test_rule_translator_realistic_samples.py` | **New** — 6 end-to-end realistic configuration samples exercising full translation path |

## Version History

| Date | Change |
|------|--------|
| 2026-05-24 | Initial matrix — covers Batch A-D fallback enhancements |
