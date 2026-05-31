from __future__ import annotations

import re
from dataclasses import dataclass

from core.parser.shared import split_config_blocks


@dataclass(frozen=True)
class ConfigBlock:
    """A top-level config block classified by broad network feature."""

    feature: str
    start_line: int
    end_line: int
    lines: list[str]
    vendor_hint: str = "unknown"

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def _matches_any(text: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE | re.MULTILINE) for pattern in patterns)


def classify_config_block(block_text: str, vendor: str = "unknown") -> str:
    """Classify a config block without claiming semantic equivalence."""

    lines = [line.strip() for line in block_text.splitlines() if line.strip()]
    if not lines:
        return "unknown"

    first = lines[0]
    text = "\n".join(lines)

    if _matches_any(first, (r"^(sysname|hostname)\b", r"^(clock|ntp|timezone)\b", r"^return$")):
        return "system"
    if _matches_any(first, (r"^vlan\s+batch\b", r"^vlan\s+\d+", r"^vlan\b")):
        return "vlan"
    if _matches_any(first, (r"^voice-vlan\b", r"^voice\s+vlan\b")):
        return "l2_voice_vlan"
    if _matches_any(first, (r"^lldp\b", r"^cdp\b")):
        return "l2_lldp"
    if _matches_any(first, (r"^mac-address\b", r"^mac\s+address-table\b")):
        return "l2_mac_table"
    if _matches_any(first, (r"^interface\b",)):
        return "interface"
    if _matches_any(first, (r"^object-group\b",)):
        return "object_group"
    if _matches_any(first, (r"^acl\s+(name|number)\b", r"^ip\s+access-list\b", r"^access-list\b")):
        return "acl"
    if _matches_any(first, (r"^ip\s+route-static\b", r"^ip\s+route\b", r"^ipv6\s+route")):
        return "route"
    if _matches_any(
        first,
        (
            r"^ip\s+(?:ip-prefix|prefix-list)\b",
            r"^(?:ip\s+)?prefix-list\b",
            r"^(?:ip\s+)?as-path-filter\b",
            r"^(?:ip\s+)?community-filter\b",
        ),
    ):
        return "route_filter"
    if _matches_any(first, (r"^(?:rip|router\s+rip)\b",)):
        return "rip"
    if _matches_any(first, (r"^(?:isis|is-is|router\s+isis|router\s+is-is)\b",)):
        return "isis"
    if _matches_any(first, (r"^ip\s+vpn-instance\b", r"^vrf\s+definition\b", r"^ip\s+vrf\b")):
        return "vrf"
    if _matches_any(first, (r"^(?:policy-based-route|ip\s+policy-based-route)\b",)):
        return "pbr"
    if _matches_any(first, (r"^(?:multicast|pim|igmp|ip\s+multicast-routing)\b",)):
        return "multicast"
    if _matches_any(
        first,
        (
            r"^traffic\s+(classifier|behavior|policy)\b",
            r"^(class-map|policy-map)\b",
            r"^qos\b",
            r"^diffserv\b",
        ),
    ) or _matches_any(text, (r"\bservice-policy\b",)):
        return "qos"
    if _matches_any(
        first,
        (
            r"^aaa\b",
            r"^authentication-profile\b",
            r"^radius-server\b",
            r"^hwtacacs-server\b",
            r"^local-user\b",
            r"^user-interface\b",
            r"^username\b",
        ),
    ):
        return "aaa"
    if _matches_any(first, (r"^snmp-agent\b", r"^snmp-server\b")):
        return "snmp"
    if _matches_any(first, (r"^nqa\s+test-instance\b", r"^ip\s+sla\b")):
        return "nqa"
    if _matches_any(first, (r"^bfd\b",)):
        return "bfd"
    if _matches_any(first, (r"^stp\b", r"^spanning-tree\b")):
        return "stp"
    if _matches_any(first, (r"^(?:nat-policy|nat\b|source-nat\b|destination-nat\b|ip\s+nat\b)",)):
        return "firewall_nat"
    if _matches_any(
        first,
        (
            r"^(?:ike|ipsec|crypto|tunnel-group)\b",
            r"^vpn\b",
        ),
    ):
        return "firewall_ipsec"
    if _matches_any(first, (r"^time-range\b",)):
        return "time_range"
    if _matches_any(
        first,
        (
            r"^(?:url-filter|antivirus|av-profile|intrusion|ips|profile|application|user-profile)\b",
        ),
    ):
        return "firewall_profile"

    # A few Huawei/H3C global commands are important to keep visible for audit,
    # but they are not safe to auto-render through generic fallback.
    if _matches_any(first, (r"^info-center\b", r"^stelnet\b", r"^ssh\b", r"^pki\b", r"^ecc\b")):
        return "system"

    return "unknown"


def split_config_by_feature(config_text: str, vendor: str = "unknown") -> list[ConfigBlock]:
    """Split config into auditable feature blocks.

    This is intentionally a coarse routing primitive, not a semantic parser.
    Downstream code may use it to decide which blocks are safe to auto-convert,
    which require manual review, and which should be kept out of executable output.
    """

    blocks: list[ConfigBlock] = []
    for block_text, start_line, end_line in split_config_blocks(config_text):
        lines = [line.rstrip() for line in block_text.splitlines() if line.strip()]
        if not lines:
            continue
        display_start = max(start_line, 1)
        display_end = max(end_line, display_start)
        blocks.append(
            ConfigBlock(
                feature=classify_config_block(block_text, vendor),
                start_line=display_start,
                end_line=display_end,
                lines=lines,
                vendor_hint=vendor or "unknown",
            )
        )
    return blocks


def summarize_feature_blocks(blocks: list[ConfigBlock]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for block in blocks:
        summary[block.feature] = summary.get(block.feature, 0) + 1
    return summary
