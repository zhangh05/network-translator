from __future__ import annotations
from core.domain import DeviceDomain
from core.renderer.base import (
    BaseRenderer, RenderContext, RenderResult,
    RenderError, ReviewItem,
    comment_line, section_separator,
)

DomainPlatformKey = tuple[DeviceDomain, str]
_renderers: dict[DomainPlatformKey, type[BaseRenderer]] = {}


def register_renderer(domain: DeviceDomain, platform: str, renderer_cls: type[BaseRenderer]) -> None:
    key = (domain, platform)
    _renderers[key] = renderer_cls


def get_renderer(domain: DeviceDomain, platform: str) -> type[BaseRenderer] | None:
    return _renderers.get((domain, platform))


def list_renderers() -> list[DomainPlatformKey]:
    return list(_renderers.keys())


def init_renderers() -> None:
    """Import all renderer modules to trigger registration."""
    import core.renderer.renderer_cisco_ios_xe
    import core.renderer.renderer_h3c_comware
    import core.renderer.renderer_huawei_vrp
    import core.renderer.renderer_huawei_usg
    import core.renderer.renderer_ruijie_rgos
    import core.renderer.renderer_hillstone_stoneos
    import core.renderer.renderer_topsec_tos
    import core.renderer.renderer_dptech_fw


__all__ = [
    "BaseRenderer", "RenderContext", "RenderResult",
    "RenderError", "ReviewItem",
    "comment_line", "section_separator",
    "DomainPlatformKey",
    "register_renderer", "get_renderer", "list_renderers", "init_renderers",
]
