import pytest
from core.parser.base import (
    BaseParser, ParserContext, ParseResult, ParseSectionResult,
    ParseError, RawLine,
)
from core.parser import register_parser, get_parser, list_parsers, DomainPlatformKey
from core.domain import DeviceDomain
from core.ir_models import IRConfig, IRConfigMeta, IRUnknownBlock
from core.ir_models.enums import IRType
from core.ir_models.base import SourceSpan


class TestRawLine:
    def test_minimal(self):
        rl = RawLine(line_no=1, raw="  vlan 10  ")
        assert rl.line_no == 1
        assert rl.normalized == ""

    def test_with_all_fields(self):
        rl = RawLine(line_no=5, raw="!", normalized="", indent=0, is_comment=True, is_blank=False)
        assert rl.is_comment is True


class TestParserContext:
    def test_defaults(self):
        ctx = ParserContext(config_text="")
        assert ctx.source_domain == DeviceDomain.SWITCH
        assert ctx.hostname is None

    def test_with_fields(self):
        ctx = ParserContext(config_text="vlan 10", source_vendor="h3c", source_platform="comware", hostname="SW01")
        assert ctx.source_vendor == "h3c"
        assert ctx.hostname == "SW01"


class TestParseResult:
    def test_coverage_ratio_full(self):
        meta = IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="c", target_platform="c",
        )
        r = ParseResult(ir=IRConfig(meta=meta), parsed_line_count=10, total_line_count=10)
        assert r.coverage_ratio == 1.0

    def test_coverage_ratio_half(self):
        meta = IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="c", target_platform="c",
        )
        r = ParseResult(ir=IRConfig(meta=meta), parsed_line_count=5, total_line_count=10)
        assert r.coverage_ratio == 0.5

    def test_coverage_ratio_zero(self):
        meta = IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="c", target_platform="c",
        )
        r = ParseResult(ir=IRConfig(meta=meta), parsed_line_count=0, total_line_count=10)
        assert r.coverage_ratio == 0.0

    def test_coverage_ratio_no_lines(self):
        meta = IRConfigMeta(
            source_vendor="h3c", target_vendor="cisco",
            source_domain=DeviceDomain.SWITCH, target_domain=DeviceDomain.SWITCH,
            source_platform="c", target_platform="c",
        )
        r = ParseResult(ir=IRConfig(meta=meta), parsed_line_count=0, total_line_count=0)
        assert r.coverage_ratio == 0.0


class TestBaseParserAbstract:
    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            BaseParser()


class TestParseError:
    def test_with_line(self):
        e = ParseError("syntax error", line_no=10, raw_line="bad command")
        assert e.line_no == 10
        assert e.raw_line == "bad command"
        assert "syntax error" in str(e)
