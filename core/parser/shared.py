from __future__ import annotations
import re
import ipaddress


def parse_vlan_range(text: str) -> list[int]:
    """Parse VLAN range strings like '1 3-5 7' or '1,3-5,7' into list of ints.

    Supports:
    - Space-separated: '1 3-5 7'
    - Comma-separated: '1,3-5,7'
    - Mixed: '1,3-5 7'
    - 'none' or '': returns empty list
    """
    if not text or text.lower() in ("none", "null", ""):
        return []
    text = re.sub(r'(?i)(\d+)\s+to\s+(\d+)', r'\1-\2', text)
    text = text.replace(",", " ")
    result: list[int] = []
    for part in text.split():
        part = part.strip()
        if not part:
            continue
        if "-" in part or "to" in part.lower():
            sep = "-" if "-" in part else "to"
            try:
                parts = part.split(sep)
                start, end = int(parts[0]), int(parts[1])
                result.extend(range(start, end + 1))
            except (ValueError, IndexError):
                continue
        else:
            try:
                result.append(int(part))
            except ValueError:
                continue
    return sorted(set(result))


def render_vlan_range(vlans: list[int]) -> str:
    """Render list of VLAN IDs into compact range string.

    [1, 2, 3, 5, 7, 8, 9] -> '1 to 3 5 7 to 9'
    """
    if not vlans:
        return ""
    sorted_vlans = sorted(set(vlans))
    ranges: list[str] = []
    start = sorted_vlans[0]
    end = sorted_vlans[0]
    for v in sorted_vlans[1:]:
        if v == end + 1:
            end = v
        else:
            if start == end:
                ranges.append(str(start))
            else:
                ranges.append(f"{start} to {end}")
            start = v
            end = v
    if start == end:
        ranges.append(str(start))
    else:
        ranges.append(f"{start} to {end}")
    return " ".join(ranges)


def cidr_to_mask(bits: int) -> str:
    """Convert CIDR prefix length to dotted-decimal mask.

    cidr_to_mask(24) -> '255.255.255.0'
    """
    if not 0 <= bits <= 32:
        raise ValueError(f"Invalid CIDR prefix length: {bits}")
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return ".".join(str((mask >> (8 * i)) & 0xFF) for i in range(3, -1, -1))


def mask_to_cidr(mask: str) -> int:
    """Convert dotted-decimal mask to CIDR prefix length.

    mask_to_cidr('255.255.255.0') -> 24
    """
    binary = "".join(f"{int(octet):08b}" for octet in mask.split("."))
    return binary.count("1")


def wildcard_to_mask(wildcard: str) -> str:
    """Convert wildcard mask to subnet mask.

    wildcard_to_mask('0.0.0.255') -> '255.255.255.0'
    """
    return ".".join(str(255 - int(octet)) for octet in wildcard.split("."))


def mask_to_wildcard(mask: str) -> str:
    """Convert subnet mask to wildcard mask.

    mask_to_wildcard('255.255.255.0') -> '0.0.0.255'
    """
    return ".".join(str(255 - int(octet)) for octet in mask.split("."))


def split_config_blocks(text: str) -> list[tuple[str, int, int]]:
    """Split config text into top-level blocks.

    Returns list of (block_text, start_line, end_line).
    A block starts at a top-level command (indent 0) and includes all
    indented child lines until the next top-level command.
    """
    if not text.strip():
        return []
    lines = text.split("\n")
    blocks: list[tuple[str, int, int]] = []
    block_start = 0
    block_lines: list[str] = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("!") or stripped.startswith("#"):
            if not block_lines:
                block_start = i + 1
            continue
        if not line.startswith(" ") and not line.startswith("\t") and block_lines:
            blocks.append(("\n".join(block_lines), block_start, i))
            block_lines = []
            block_start = i + 1
        block_lines.append(stripped)
    if block_lines:
        blocks.append(("\n".join(block_lines), block_start, len(lines)))
    return blocks


def normalize_interface_name(name: str) -> str:
    """Quick normalization for common interface names.

    For full normalization with vendor profiles, use InterfaceNaming.normalize().
    This handles cross-vendor common prefixes.
    """
    name = re.sub(r"(?i)Vlan-?interface(\d+)", r"Vlan\1", name)
    name = re.sub(r"(?i)Vlanif(\d+)", r"Vlan\1", name)
    name = re.sub(r"(?i)Bridge-Aggregation(\d+)", r"PortChannel\1", name)
    name = re.sub(r"(?i)Eth-Trunk(\d+)", r"PortChannel\1", name)
    name = re.sub(r"(?i)Port-Channel(\d+)", r"PortChannel\1", name)
    name = re.sub(r"(?i)port-channel(\d+)", r"PortChannel\1", name)
    name = re.sub(r"(?i)^(Vlan)(\d+)$", lambda m: f"Vlan{m.group(2)}", name)
    name = re.sub(r"(?i)^(PortChannel)(\d+)$", lambda m: f"PortChannel{m.group(2)}", name)
    name = re.sub(r"(?i)^(Loopback)(\d+)$", lambda m: f"Loopback{m.group(2)}", name)
    name = re.sub(r"(?i)^(Tunnel)(\d+)$", lambda m: f"Tunnel{m.group(2)}", name)
    return name
