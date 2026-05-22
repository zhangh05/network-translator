from __future__ import annotations
from core.domain import DeviceDomain
from core.parser.base import (
    BaseParser, ParserContext, ParseResult, ParseSectionResult,
    ParseError, RawLine,
)
from core.parser.shared import (
    parse_vlan_range, render_vlan_range,
    cidr_to_mask, mask_to_cidr,
    wildcard_to_mask, mask_to_wildcard,
    split_config_blocks, normalize_interface_name,
)

DomainPlatformKey = tuple[DeviceDomain, str]
_parsers: dict[DomainPlatformKey, type[BaseParser]] = {}


def register_parser(domain: DeviceDomain, platform: str, parser_cls: type[BaseParser]) -> None:
    key = (domain, platform)
    _parsers[key] = parser_cls


def get_parser(domain: DeviceDomain, platform: str) -> type[BaseParser] | None:
    return _parsers.get((domain, platform))


def list_parsers() -> list[DomainPlatformKey]:
    return list(_parsers.keys())


def init_parsers() -> None:
    """Import all parser modules to trigger registration."""
    import core.parser.parser_h3c_comware
    import core.parser.parser_huawei_vrp
    import core.parser.parser_huawei_usg
    import core.parser.parser_cisco_ios_xe
    import core.parser.parser_ruijie_rgos
    import core.parser.parser_hillstone_stoneos
    import core.parser.parser_topsec_tos
    import core.parser.parser_dptech_fw


__all__ = [
    "BaseParser", "ParserContext", "ParseResult", "ParseSectionResult",
    "ParseError", "RawLine",
    "parse_vlan_range", "render_vlan_range",
    "cidr_to_mask", "mask_to_cidr",
    "wildcard_to_mask", "mask_to_wildcard",
    "split_config_blocks", "normalize_interface_name",
    "DomainPlatformKey",
    "register_parser", "get_parser", "list_parsers", "init_parsers",
]
