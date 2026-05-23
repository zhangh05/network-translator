from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from core.ir_models import IRConfig
from core.ir_models.enums import ConversionStatus, IRRiskLevel


@dataclass
class RenderContext:
    """Context for rendering IRConfig into target vendor config text."""
    profile_key: str = ""
    comment_char: str = "!"
    render_header: bool = True
    render_unknown_blocks: bool = True
    render_unsupported: bool = True
    line_ending: str = "\n"


class RenderError(Exception):
    """Raised when rendering encounters a fatal error."""
    def __init__(self, message: str, field: str | None = None, raw: str | None = None):
        self.field = field
        self.raw = raw
        super().__init__(message)


@dataclass
class ReviewItem:
    """An item that needs human review."""
    field: str
    description: str
    severity: str = "info"
    line: int | None = None
    source_text: str | None = None
    suggestion: str | None = None


@dataclass
class RenderResult:
    """Complete result of rendering IRConfig to target config text."""
    config_text: str
    features_rendered: list[str] = field(default_factory=list)
    features_skipped: list[str] = field(default_factory=list)
    review_items: list[ReviewItem] = field(default_factory=list)
    errors: list[RenderError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class BaseRenderer(ABC):
    """Abstract base class for all config renderers.

    Subclasses implement render_* methods for specific IR types.
    The top-level render() method dispatches to type-specific methods
    in a fixed order, then appends unknown/unsupported blocks as comments.
    """

    vendor: str = ""
    platform: str = ""
    comment_char: str = "!"

    def __init__(self, profile_key: str = ""):
        self._profile_key = profile_key

    @abstractmethod
    def render(self, ir: IRConfig, context: RenderContext | None = None) -> RenderResult:
        """Render IRConfig to target vendor config text."""

    @staticmethod
    def comment_line(text: str, comment_char: str = "!") -> str:
        """Wrap a line as a comment."""
        return f"{comment_char} {text}"

    @staticmethod
    def section_separator(comment_char: str = "!") -> str:
        """Return a section separator line."""
        return f"{comment_char} {'-' * 70}"

    @staticmethod
    def format_output(text: str) -> str:
        """Normalize output: ensure single trailing newline, no trailing whitespace on lines."""
        lines = text.split("\n")
        cleaned = "\n".join(line.rstrip() for line in lines)
        return cleaned.rstrip("\n") + "\n"

    def render_as_comment(self, text: str, comment_char: str | None = None) -> str:
        """Render arbitrary text with every line commented out."""
        cc = comment_char or self.comment_char
        if not text.strip():
            return ""
        lines = text.split("\n")
        return "\n".join(f"{cc} {line.strip()}" for line in lines)


def comment_line(text: str, comment_char: str = "!") -> str:
    """Standalone helper: wrap a line as a comment."""
    return f"{comment_char} {text}"


def section_separator(comment_char: str = "!") -> str:
    """Standalone helper: return a section separator line."""
    return f"{comment_char} {'-' * 70}"
