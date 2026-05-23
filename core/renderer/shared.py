from __future__ import annotations
from core.renderer.base import comment_line, section_separator


def render_vlan_range(vlans: list[int]) -> str:
    """Render list of VLAN IDs into vendor format string.

    [1, 2, 3, 5, 7, 8, 9] -> '1-3,5,7-9'
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
                ranges.append(f"{start}-{end}")
            start = v
            end = v
    if start == end:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{end}")
    return ",".join(ranges)


def indent_line(line: str, level: int = 1, indent_str: str = " ") -> str:
    """Add indentation to a line."""
    return indent_str * level + line


__all__ = [
    "comment_line", "section_separator",
    "render_vlan_range", "indent_line",
]
