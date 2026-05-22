from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from core.domain import DeviceDomain
from core.ir_models import IRConfig, IRConfigMeta, IRUnknownBlock
from core.ir_models.enums import IRType
from core.ir_models.base import SourceSpan


@dataclass
class RawLine:
    """A single line of raw config with metadata."""
    line_no: int
    raw: str
    normalized: str = ""
    indent: int = 0
    is_comment: bool = False
    is_blank: bool = False


@dataclass
class ParserContext:
    """Context passed through the parsing pipeline."""
    config_text: str
    source_vendor: str = ""
    target_vendor: str = ""
    source_domain: DeviceDomain = DeviceDomain.SWITCH
    target_domain: DeviceDomain = DeviceDomain.SWITCH
    source_platform: str = ""
    target_platform: str = ""
    hostname: str | None = None
    file_path: str | None = None


class ParseError(Exception):
    """Raised when parsing encounters a fatal error."""
    def __init__(self, message: str, line_no: int | None = None, raw_line: str | None = None):
        self.line_no = line_no
        self.raw_line = raw_line
        super().__init__(message)


@dataclass
class ParseSectionResult:
    """Result of parsing a single section (e.g., one VLAN block)."""
    ir_type: IRType
    ir_objects: list = field(default_factory=list)
    parsed_lines: int = 0
    errors: list[ParseError] = field(default_factory=list)


@dataclass
class ParseResult:
    """Complete result of parsing a config file."""
    ir: IRConfig
    parsed_line_count: int = 0
    total_line_count: int = 0
    errors: list[ParseError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    section_results: list[ParseSectionResult] = field(default_factory=list)
    unknown_lines: list[int] = field(default_factory=list)

    @property
    def coverage_ratio(self) -> float:
        if self.total_line_count == 0:
            return 0.0
        return round(self.parsed_line_count / self.total_line_count, 4)


class BaseParser(ABC):
    """Abstract base class for all config parsers.

    Subclasses should register themselves via register_parser in __init__.py.
    The default parse() method iterates lines and calls parse_* methods.
    Unknown/unrecognized lines are collected into IRUnknownBlock.
    """

    vendor: str = ""
    platform: str = ""
    supported_domains: list[DeviceDomain] = []

    def __init__(self, domain: DeviceDomain | None = None):
        self._domain = domain or (self.supported_domains[0] if self.supported_domains else DeviceDomain.SWITCH)

    @abstractmethod
    def parse(self, config_text: str, context: ParserContext | None = None) -> ParseResult:
        """Parse config text into IRConfig."""

    def make_meta(self, context: ParserContext | None = None) -> IRConfigMeta:
        ctx = context or ParserContext(config_text="")
        return IRConfigMeta(
            source_vendor=ctx.source_vendor or self.vendor,
            target_vendor=ctx.target_vendor or "unknown",
            source_domain=ctx.source_domain or self._domain,
            target_domain=ctx.target_domain or DeviceDomain.SWITCH,
            source_platform=ctx.source_platform or self.platform,
            target_platform=ctx.target_platform or "unknown",
            hostname=ctx.hostname,
        )

    def collect_unknown(
        self,
        lines: list[RawLine],
        start_line: int = 1,
        end_line: int | None = None,
    ) -> list[IRUnknownBlock]:
        """Collect lines that were not parsed into any known IR type."""
        if not lines:
            return []
        end_line = end_line or lines[-1].line_no
        raw_text = "\n".join(l.raw for l in lines if not l.is_comment)
        if not raw_text.strip():
            return []
        span = SourceSpan(start_line=start_line, end_line=end_line)
        return [IRUnknownBlock(type=IRType.UNKNOWN, source_span=span, raw_text=raw_text)]
