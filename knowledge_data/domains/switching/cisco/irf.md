# H3C IRF → Cisco Equivalent Guide

## Overview
H3C IRF (Intelligent Resilient Framework) is H3C's device virtualization/stacking
technology. It has **no direct equivalent** in standard Cisco IOS.

## Cisco Equivalent (Platform-Dependent)

| Technology | Applicable Platforms | Limitation |
|------------|---------------------|------------|
| StackWise | Catalyst 3750/3850/9300 | Hardware-specific, not CLI-equivalent |
| StackWise Virtual | Catalyst 4500/9500 | High-end only, not general IOS |
| VSS | Catalyst 6500/6800 | Legacy, not available on modern platforms |
| vPC | Nexus series | Layer-2 only, no control-plane merge |

For **common Cisco IOS targets** (without StackWise/VSS capability):
- There is **no command-level equivalent** for IRF member/IRF-port/IRF-port-configuration
- **Do NOT translate IRF commands to Port-channel or LACP** — these are link
  aggregation, not chassis virtualization
- Output should use MANUAL_REVIEW markers

## Translation Guidance
- If target platform has VSS/StackWise Virtual, mapping is possible but
  requires manual verification
- For plain Cisco IOS/NX-OS without virtualization support:
  - `translated_lines` should be empty
  - `notes` should explain: "IRF is H3C-specific; Cisco IOS has no equivalent."
- Mark all IRF-related output as manual_review_required=true,
  deployable=false

## Important
- Do NOT include source vendor (H3C) commands or feature names in the
  translated output, even in comments. Comments should focus on what the
  target configuration does, not what the source had.
- If no Cisco equivalent exists, output a MANUAL_REVIEW comment. Never
  silently drop IRF functionality without acknowledgment.
- The translated_lines for IRF features must always include at minimum
  a MANUAL_REVIEW comment explaining the gap.
