# H3C IRF (Intelligent Resilient Framework)

## Overview
IRF is H3C's device virtualization/stacking technology that combines multiple
physical switches into a single logical device. It provides:
- Multi-chassis link aggregation (cross-member)
- Distributed forwarding and HA
- Single management plane

## Cisco Equivalent
Cisco has **no single command equivalent** for H3C IRF. Depending on target
hardware platform, different technologies apply:

| Technology | Platform | Similarity |
|------------|----------|------------|
| StackWise | Catalyst 3750/3850/9300 | Fan-out stacking, limited to specific models |
| StackWise Virtual | Catalyst 4500/6800/9500 | Multi-chassis L2/L3 virtualization |
| VSS | Catalyst 6500/6800 | Multi-chassis L2/L3 virtualization (EOL migration) |
| vPC | Nexus 5000/7000/9000 | Multi-chassis port-channel only, no control-plane merge |
| StackPower | Catalyst 3850/9300 | Power stacking only, not a full IRF equivalent |

## Key Constraints
- IRF features (member/priority/IRF-port binding/IRF-port-configuration/mad)
  have **no direct Cisco IOS equivalent**.
- **Do NOT translate IRF commands to Port-channel or LACP** — they are
  fundamentally different technologies (virtual chassis vs link aggregation).
- For common Cisco IOS (non-StackWise/VSS) targets:
  - Output empty translated_lines with MANUAL_REVIEW
  - Notes should explain: "IRF is H3C-specific; Cisco IOS has no equivalent."
- For target platforms with VSS/StackWise capability:
  - `irf member 1` → `switch 1` (StackWise Virtual)
  - `irf-port 1/1` → Requires manual mapping to virtual stack ports
  - `irf-port-configuration active` → `switch virtual domain 1`
  - Priority mapping: `irf member 1 priority X` → `switch 1 priority X`
- Mark all IRF-related translated output as manual_review_required.

## Recommendation
Default to manual_review_required=true. Only attempt automatic equivalence
when target platform is confirmed VSS/StackWise-capable.

## Important
- Do NOT include source vendor (H3C) commands or feature names in the
  translated output, even in comments. Comments should explain the target
  configuration, not reference source features by name.
- Output only MANUAL_REVIEW comments without mentioning `irf member`,
  `irf-port`, or other H3C-specific commands.
