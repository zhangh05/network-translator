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

### Access authentication / NAC — ALWAYS MANUAL_REVIEW

准入认证不是简单语法替换能力。802.1X、MAC 认证、Portal、RADIUS scheme/domain、失败动作、critical VLAN、接口授权模式会共同决定终端能否入网。本项目当前只做**识别、拆模块、关联证据、脱敏、人工复核**，不自动生成等价可执行配置。

| Command pattern | Module feature | Behavior |
|-----------------|----------------|----------|
| `authentication-profile name NAME` | `access.auth_profile` | MANUAL_REVIEW, provides `auth-profile:NAME` |
| `dot1x-access-profile NAME` / `dot1x ...` | `access.dot1x` | MANUAL_REVIEW |
| `mac-access-profile NAME` / `mac-authentication ...` / `mab` | `access.mac_auth` | MANUAL_REVIEW |
| `portal server NAME ...` | `access.portal` | MANUAL_REVIEW |
| `radius scheme NAME` / `domain NAME` / `authentication lan-access radius-scheme NAME` | `access.radius_binding` | MANUAL_REVIEW, secrets redacted |
| Interface `authentication-profile NAME`, `dot1x enable`, `mac-authentication enable`, `authentication port-control`, `access-session ...` | `access.interface_binding` | MANUAL_REVIEW, linked to `interface:*` and `auth-profile:*` where detectable |

**Safety rule**: access-authentication commands must not pass through as executable fallback output. Shared keys and cipher values are always `<redacted>`.

### Management line (VTY/Console/AUX) — ALWAYS MANUAL_REVIEW

管理入口 line vty/con/aux 和 user-interface vty/console/aux 涉及管理面安全。认证方式、传输协议、会话超时和访问控制列表跨厂商语义不同，不自动生成可执行配置。

| Command pattern | Module feature | Behavior |
|-----------------|----------------|----------|
| `line vty 0 4` / `line con 0` / `line aux 0` | `management.line` | MANUAL_REVIEW, semantic_near skeleton |
| `user-interface vty 0 4` / `user-interface console 0` | `management.line` | MANUAL_REVIEW, semantic_near skeleton, password redacted |

### Interface range — ALWAYS MANUAL_REVIEW

接口批量 range 声明的展开方式和子命令作用域跨厂商不同，不自动生成可执行配置。

| Command pattern | Module feature | Behavior |
|-----------------|----------------|----------|
| `interface range Gi0/0/1 to Gi0/0/24` | `interface.range` | MANUAL_REVIEW, semantic_near skeleton |

### Track objects — ALWAYS MANUAL_REVIEW

Track/NQA/IP SLA 探测对象的类型、联动动作和告警语义跨厂商不同，不自动生成可执行配置。

| Command pattern | Module feature | Behavior |
|-----------------|----------------|----------|
| `track 1 ip route 10.0.0.0/8 reachability` | `track` | MANUAL_REVIEW, semantic_near skeleton |
| `track track1 interface Gi0/0/1 line-protocol` | `track` | MANUAL_REVIEW, semantic_near skeleton |

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

### QoS — Interface binding only (safe subset, Batch I-F)

**Only binding lines are auto-translated. Policy bodies are always MANUAL_REVIEW.**

| Source | Target | Conditions |
|--------|--------|------------|
| `traffic-policy P inbound` (Huawei/H3C) | Cisco | `service-policy input P` (binding only) |
| `traffic-policy P outbound` (Huawei/H3C) | Cisco | `service-policy output P` (binding only) |
| `service-policy input P` (Cisco) | Huawei/H3C | `traffic-policy P inbound` (binding only) |
| `service-policy output P` (Cisco) | Huawei/H3C | `traffic-policy P outbound` (binding only) |

**Everything inside `traffic-policy / traffic-classifier / traffic-behavior / car / remark dscp / queue / policy-map / class-map / police / priority / bandwidth / shape`** → MANUAL_REVIEW.

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
| OSPF area authentication message-digest | MANUAL_REVIEW |
| BGP neighbor sub-commands (description, update-source, password) | MANUAL_REVIEW — password always `<redacted>` + MANUAL_REVIEW |
| BGP peer sub-commands (connect-interface, ebgp-multihop, password) | MANUAL_REVIEW — password always `<redacted>` + MANUAL_REVIEW |
| route-map / route-policy skeleton (Batch I-F) | `route-map NAME permit/deny SEQ` ↔ `route-policy NAME permit/deny node SEQ` — skeleton only. `if-match acl ACL` ↔ `match ip address ACL` auto. `apply local-preference N` ↔ `set local-preference N` auto. |
| route-map / route-policy body commands | MANUAL_REVIEW — continue, call, community (always `<redacted>`), as-path, tag, extcommunity, metric, and all other match/set sub-commands are not auto-translated |

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
| Hillstone | Huawei USG | Zone / address / service / policy | Complete flat policy with all required fields. Valid subnet addresses (`IP + netmask`) auto. Address range (`IP1 IP2` non-netmask) and `host` keyword → MANUAL_REVIEW |
| Topsec | Huawei USG | Zone | `zone name <zone>` |
| Topsec | Huawei USG | Address object | `address name NAME ip A.B.C.D mask MMM.MMM.MMM.MMM` → `ip address-set NAME type object` + `address 0 A.B.C.D mask MMM.MMM.MMM.MMM` |
| Topsec | Huawei USG | Policy | Only when **all 6 fields present**: source-zone, destination-zone, source-address, destination-address, service, action. Output: `security-policy` + `rule name ...` block |
| Hillstone | Topsec | Zone | `zone <zone>` → `zone name <zone>` |
| Hillstone | Topsec | Address object | `address NAME IP MASK` / `address NAME IP host` → `address name NAME ip IP mask MASK` |
| Hillstone | Topsec | Policy | Only when **all required fields present**: from, to, source, destination, service, action. Output: Topsec `policy name ...` format |
| DPtech | Huawei USG | Zone / address / policy | Complete policy with all required fields |
| DPtech | Hillstone | Zone / policy | Complete policy with all required fields |
| Topsec | Topsec | Passthrough | Same-vendor; non-dangerous commands pass through unchanged |
| Topsec | Huawei USG | Service object | `service NAME protocol tcp/udp/icmp destination-port N` → `ip service-set NAME type object` + `service 0 protocol tcp/udp/icmp destination-port N`. Port range/source-port/multi-port → MANUAL_REVIEW |
| Hillstone | Huawei USG | Service object | `service NAME tcp/udp N` / `service NAME tcp/udp dst-port N` → `ip service-set NAME type object` + `service 0 protocol tcp/udp destination-port N`. Port range/multi-port → MANUAL_REVIEW |
| Huawei USG | Hillstone | Service object | `ip service-set NAME type object` + `service 0 protocol tcp/udp destination-port N` → `service NAME tcp/udp N` (no `dst-port` keyword per Batch I-F spec). Port range/source-port/multi-port → MANUAL_REVIEW |
| Hillstone | Topsec | Service object | `service NAME tcp/udp N` → `service NAME protocol tcp/udp destination-port N`. ICMP: `service NAME icmp` → `service NAME protocol icmp`. Port range/multi-port → MANUAL_REVIEW |
| Topsec | Hillstone | Service object | `service NAME protocol tcp/udp destination-port N` → `service NAME tcp/udp N`. ICMP: `service NAME protocol icmp` → `service NAME icmp` |

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
| Hillstone | Huawei USG | NAT, IPSec, VPN, URL filter, AV, time-range, log, session, profile, application, user, address range (IP IP non-netmask), address host keyword |
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
| `tests/test_rule_translator_firewall_objects.py` | Firewall object/policy details — 108 tests |
| `tests/test_rule_translator_firewall_service_objects.py` | Firewall service objects — 19 tests |
| `tests/test_rule_translator_switch_batch_k.py` | SWITCH Batch K-A — trunk add/remove/all/none, native vlan↔pvid, interface range, STP guard/bpdu-protection — 49 tests |
| `tests/test_rule_translator_router_batch_k.py` | ROUTER Batch K-B — static route options, OSPF authentication, BGP password/update-source/ebgp-multihop, VRF policy, route-policy community redaction — 30 tests |
| `tests/test_rule_translator_firewall_batch_k.py` | FIREWALL Batch K-C — address range/group, service-set, dangerous guard, zone bind — 14 tests |
| `tests/test_safe_fallback_and_block_splitter.py` | Infrastructure (safe fallback guard, splitter) |
| `tests/test_rule_translator_switch_multivendor.py` | SWITCH (12 direction pairs + negatives) |
| `tests/test_rule_translator_router_multivendor.py` | ROUTER (static/OSPF/BGP/VRF multi-direction) |
| `tests/test_rule_translator_management.py` | MANAGEMENT (NTP/logging/SNMP/AAA/access-auth/hostname) — 82 tests |
| `tests/test_rule_translator_acl_binding.py` | ACL and interface binding — 59 tests |
| `tests/test_realistic_fallback_report.py` | Fallback report structure and redaction — 27 tests |
| `tests/test_rule_translator_realistic_samples.py` | 6 end-to-end realistic samples |
| `tests/test_fallback_capability_matrix.py` | Capability matrix — 13 tests |
| `tests/test_rule_translator_realistic_batch_i_e.py` | Realistic medium-length configs (4 directions) — 21 tests |
| `tests/test_rule_translator_realistic_batch_k.py` | Realistic multi-vendor configs (8 directions) — 45 tests |
| `tests/test_corpus_samples.py` | Corpus manifest + sample file validation — 21 tests |
| `tests/test_corpus_fallback_evaluator.py` | Corpus fallback evaluator infrastructure — 5 tests |
| `tests/test_fallback_gap_analysis_doc.py` | Gap analysis document consistency — 5 tests |
| `tests/test_module_graph_batch_o_expansion.py` | Module graph Batch O expansion — 75 tests |
| `tests/test_rule_translator_batch_o_breadth.py` | Fallback rule Batch O breadth — 44 tests |

### Corpus Evaluation

The project maintains a multi-vendor sample corpus at `corpus/sanitized_samples/` with 22 sanitized configuration files covering all 8 vendor platforms and 3 domains. The corpus is evaluated by `scripts/evaluate_corpus_fallback.py`, which runs every (sample, target) pair through the fallback translator and checks for:

- **Manual review compliance**: Features requiring manual review are properly marked
- **Source residue**: No executable source-vendor commands remain in output (target-aware)
- **Secret leakage**: No credential material leaks into output

Known evaluation gaps are documented in `docs/FALLBACK_GAP_ANALYSIS.md`. As of Batch O, all 54 sample-target pairs pass (100%).

## Version History

| Date | Change |
|------|--------|
| 2026-05-25 Batch L | Added corpus evaluation section, test coverage for corpus tests (15 + 5 + 5 = 25 new tests), gap analysis reference |

## Version History

| Date | Change |
|------|--------|
| 2026-05-24 | Initial matrix — covers Batch A-D fallback enhancements |
| 2026-05-24 Batch I | Added MANAGEMENT section, ACL/QoS section, updated firewall source-path table, clarified AAA/password rules and no-implicit-any policy |
| 2026-05-24 Batch I-B | MANAGEMENT: NTP source-interface (H3C/Ruijie), logging facility/manual_review, radius/tacacs key redaction, 37 new tests (79 total) |
| 2026-05-24 Batch I-C | ACL/QoS: H3C→Huawei packet-filter, Cisco named ACL header, Huawei ACL rule→Cisco, object-group/manual_review guards, 32 new tests (59 total) |
| 2026-05-25 Batch I-D | FIREWALL: Topsec→Huawei USG (zone/address/policy), Hillstone→Topsec (zone/address/policy), DPtech completeness, dangerous feature guards, address mask netmask format, Topsec routing fix (non-Topsec/Hillstone sources to Topsec → MANUAL_REVIEW), 84 firewall tests |
| 2026-05-25 Batch I-E | Realistic samples: Cisco→Huawei trunk/access/SVI/ACL/OSPF/NTP/AAA, Huawei→Cisco Vlanif/ACL/OSPF/SNMP/AAA, Topsec→Huawei USG complete policy, Hillstone→Topsec complete policy. Fix: no switchport (Cisco routed-port) dropped in Huawei output, BGP neighbor password redacted in MANUAL_REVIEW. New test file: 21 realistic tests |
| 2026-05-25 Batch I-F | Firewall service objects (Topsec↔Huawei USG↔Hillstone), route-policy skeleton (Cisco↔Huawei), QoS binding safe subset, NAT guard (all NAT → MANUAL_REVIEW). Hillstone service format: `service NAME proto PORT` without `dst-port` keyword per Batch I-F spec. Added route-policy skeleton to ROUTER domain section. |
| 2026-06-01 QoS binding convergence | `traffic-policy P outbound` now maps to `service-policy output P`; `service-policy output P` maps to `traffic-policy P outbound`. QoS policy bodies remain MANUAL_REVIEW. |
| 2026-05-25 Batch K-A | SWITCH: trunk allowed vlan add/remove/all/none, access vlan↔port default vlan, native vlan↔pvid, interface range → MANUAL_REVIEW, STP bpdu-protection→spanning-tree bpduguard, undo port trunk permit vlan→undo port trunk allow-pass vlan. 49 new tests (1371/0/3 CI). |
| 2026-05-25 Batch K-B | ROUTER: static route name/tag/preference/distance/track/bfd → MANUAL_REVIEW, OSPF area authentication → MANUAL_REVIEW, BGP update-source→connect-interface MANUAL_REVIEW, BGP ebgp-multihop → MANUAL_REVIEW, BGP password redaction (`peer` direction + `.+` eat-all regex), route-policy set community → redacted + MANUAL_REVIEW, VRF import/export policy → MANUAL_REVIEW. Bugfix: passive-interface/silent-interface preserve original interface name case. 30 new tests (1925/0/23 CI). |
| 2026-05-25 Batch K-C | FIREWALL: Hillstone address range (two IP non-netmask) -> Huawei USG MANUAL_REVIEW (BUGFIX: was wrongly auto-translated as `mask 9`). Hillstone address `host` keyword -> Huawei USG MANUAL_REVIEW (was producing invalid `mask host`). Plus 12 regression tests for address-group/service-set/zone-bind/nat dangerous guards. 14 new tests (1939/0/23 CI). |
| 2026-05-25 Batch K-D | Realistic end-to-end multi-vendor samples (8 chains: Cisco/Huawei/H3C/Ruijie switch + router + Huawei USG/Hillstone firewall). 45 new tests covering auto-translate verification, MANUAL_REVIEW guard verification, secret leak detection, source residue check, no-implicit-any policy. Updated test coverage summary. (1984/0/23 CI). |
| 2026-06-02 Batch O | Module graph expansion: management.banner/dns/archive/clock, dhcp.pool, ipv6 ospf, unknown fallback semantic_near. Fallback rule expansion: address-family guard (huawei), ipsec/ike/crypto/vpn/tunnel-group guard (huawei), peer guard (ruijie), stp mode guard (cisco). Corpus expanded from 10 to 22 samples (54 pairs, 100% pass). Secret auto-redaction in `manual_review_comment`. New test files: 75 module-graph tests + 44 fallback-breadth tests. (2495/0/29 pytest; 1970/0/10 CI). |
