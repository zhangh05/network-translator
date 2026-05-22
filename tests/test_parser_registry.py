import pytest
from core.parser import (
    register_parser, get_parser, list_parsers, init_parsers, DomainPlatformKey,
)
from core.domain import DeviceDomain
from core.parser.base import BaseParser, ParserContext, ParseResult


class TestRegistry:
    def test_empty_before_init(self):
        """Before init_parsers(), no parsers should be registered."""
        pass

    def test_init_registers_all(self):
        init_parsers()
        registered = list_parsers()
        keys = set(registered)

        assert (DeviceDomain.SWITCH, "comware") in keys
        assert (DeviceDomain.ROUTER, "comware") in keys
        assert (DeviceDomain.SWITCH, "ios-xe") in keys
        assert (DeviceDomain.ROUTER, "ios-xe") in keys
        assert (DeviceDomain.SWITCH, "vrp") in keys
        assert (DeviceDomain.ROUTER, "vrp") in keys
        assert (DeviceDomain.FIREWALL, "usg") in keys
        assert (DeviceDomain.SWITCH, "rg-os") in keys
        assert (DeviceDomain.ROUTER, "rg-os") in keys
        assert (DeviceDomain.FIREWALL, "stoneos") in keys
        assert (DeviceDomain.FIREWALL, "tos") in keys
        assert (DeviceDomain.FIREWALL, "dp-firewall") in keys


class TestGetParser:
    def test_get_h3c_comware_switch(self):
        init_parsers()
        parser_cls = get_parser(DeviceDomain.SWITCH, "comware")
        assert parser_cls is not None
        assert parser_cls.vendor == "h3c"

    def test_get_h3c_comware_router(self):
        init_parsers()
        parser_cls = get_parser(DeviceDomain.ROUTER, "comware")
        assert parser_cls is not None

    def test_get_huawei_usg_firewall(self):
        init_parsers()
        parser_cls = get_parser(DeviceDomain.FIREWALL, "usg")
        assert parser_cls is not None
        assert parser_cls.vendor == "huawei"

    def test_get_cisco_ios_xe_switch(self):
        init_parsers()
        parser_cls = get_parser(DeviceDomain.SWITCH, "ios-xe")
        assert parser_cls is not None

    def test_get_nonexistent_returns_none(self):
        parser_cls = get_parser(DeviceDomain.FIREWALL, "nonexistent")
        assert parser_cls is None


class TestSkeletonParser:
    def test_h3c_skeleton_returns_unknown_blocks(self):
        init_parsers()
        parser_cls = get_parser(DeviceDomain.SWITCH, "comware")
        p = parser_cls()
        result = p.parse("vlan 10\n port access vlan 10\n")
        assert result.total_line_count == 2
        assert result.parsed_line_count == 0
        assert result.coverage_ratio == 0.0
        assert len(result.ir.unknown_blocks) >= 1

    def test_empty_config_no_crash(self):
        init_parsers()
        parser_cls = get_parser(DeviceDomain.SWITCH, "comware")
        p = parser_cls()
        result = p.parse("")
        assert result.total_line_count == 0

    def test_huawei_usg_skeleton_returns_unknown_blocks(self):
        init_parsers()
        parser_cls = get_parser(DeviceDomain.FIREWALL, "usg")
        p = parser_cls()
        result = p.parse("security-zone name trust\n")
        assert result.coverage_ratio == 0.0
