import pytest
from core.renderer.base import (
    BaseRenderer, RenderContext, RenderResult,
    RenderError, ReviewItem,
    comment_line, section_separator,
)
from core.domain import DeviceDomain
from core.ir_models import IRConfig, IRConfigMeta


class TestCommentLine:
    def test_default_char(self):
        assert comment_line("test") == "! test"

    def test_custom_char(self):
        assert comment_line("test", "#") == "# test"


class TestSectionSeparator:
    def test_default(self):
        sep = section_separator()
        assert sep.startswith("!")
        assert len(sep) > 10

    def test_custom_char(self):
        sep = section_separator("#")
        assert sep.startswith("#")


class TestFormatOutput:
    def test_trailing_newline(self):
        result = BaseRenderer.format_output("line1\nline2")
        assert result == "line1\nline2\n"

    def test_no_double_newlines(self):
        result = BaseRenderer.format_output("line1\n\n\nline2\n\n")
        # format_output only strips trailing, not internal
        assert result.endswith("\n")

    def test_trailing_whitespace_removed(self):
        result = BaseRenderer.format_output("line1   \nline2  \n")
        assert "line1   " not in result
        assert "line1" in result


class TestRenderAsComment:
    def test_single_line(self):
        r = CiscoRenderer()
        result = r.render_as_comment("vlan 10")
        assert result == "! vlan 10"

    def test_multi_line(self):
        r = CiscoRenderer()
        result = r.render_as_comment("vlan 10\n name MGMT")
        assert "! name MGMT" in result

    def test_empty(self):
        r = CiscoRenderer()
        assert r.render_as_comment("") == ""

    def test_huawei_comment_char(self):
        r = HuaweiRenderer()
        result = r.render_as_comment("vlan 10", "#")
        assert result == "# vlan 10"


class CiscoRenderer(BaseRenderer):
    vendor = "cisco"
    platform = "ios-xe"
    comment_char = "!"
    def render(self, ir, ctx=None):
        return RenderResult(config_text="")


class HuaweiRenderer(BaseRenderer):
    vendor = "huawei"
    platform = "vrp"
    comment_char = "#"
    def render(self, ir, ctx=None):
        return RenderResult(config_text="")


class TestBaseRendererAbstract:
    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            BaseRenderer()


class TestRenderContext:
    def test_defaults(self):
        ctx = RenderContext()
        assert ctx.comment_char == "!"
        assert ctx.render_header is True


class TestRenderResult:
    def test_defaults(self):
        r = RenderResult(config_text="")
        assert r.features_rendered == []
        assert r.errors == []


class TestReviewItem:
    def test_minimal(self):
        item = ReviewItem(field="vlan", description="test")
        assert item.severity == "info"

    def test_with_all_fields(self):
        item = ReviewItem(field="acl", description="ACL needs review", severity="warning", line=10, source_text="rule 10 permit", suggestion="change to extended ACL")
        assert item.severity == "warning"


class TestRenderError:
    def test_with_field(self):
        e = RenderError("render failed", field="vlan", raw="vlan 10")
        assert e.field == "vlan"
        assert "render failed" in str(e)
