from __future__ import annotations
from core.domain import DeviceDomain
from core.parser import register_parser, BaseParser, ParserContext, ParseResult
from core.ir_models import IRConfig, IRUnknownBlock
from core.ir_models.enums import IRType
from core.ir_models.base import SourceSpan


class TopsecTOSParser(BaseParser):
    vendor = "topsec"
    platform = "tos"
    supported_domains = [DeviceDomain.FIREWALL]

    def parse(self, config_text: str, context: ParserContext | None = None) -> ParseResult:
        meta = self.make_meta(context)
        ir = IRConfig(meta=meta)

        if not config_text or not config_text.strip():
            return ParseResult(ir=ir, parsed_line_count=0, total_line_count=0, unknown_lines=[])

        lines = config_text.rstrip("\n").split("\n")
        total = len(lines)
        span = SourceSpan(start_line=1, end_line=total)
        ir.unknown_blocks.append(
            IRUnknownBlock(type=IRType.UNKNOWN, source_span=span, raw_text=config_text)
        )
        unknown_lines = list(range(1, total + 1))

        return ParseResult(ir=ir, parsed_line_count=0, total_line_count=total, unknown_lines=unknown_lines)


register_parser(DeviceDomain.FIREWALL, "tos", TopsecTOSParser)
