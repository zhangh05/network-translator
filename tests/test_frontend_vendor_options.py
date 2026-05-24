from pathlib import Path
import re


HTML = Path("frontend/index.html").read_text(encoding="utf-8")


def _select_options(select_id: str) -> dict[str, str]:
    match = re.search(rf'<select id="{select_id}"[^>]*>(.*?)</select>', HTML, re.S)
    assert match, f"select #{select_id} not found"
    return dict(re.findall(r'<option value="([^"]*)">([^<]+)</option>', match.group(1)))


def test_frontend_source_vendor_dropdown_lists_all_supported_vendors():
    options = _select_options("fv")

    assert options["auto"] == "自动检测"
    assert options["cisco"] == "Cisco"
    assert options["huawei"] == "华为"
    assert options["h3c"] == "华三"
    assert options["ruijie"] == "锐捷"
    assert options["hillstone"] == "山石"
    assert options["topsec"] == "天融信"
    assert options["dptech"] == "迪普"


def test_frontend_target_vendor_dropdown_lists_all_supported_vendors():
    options = _select_options("tv")

    assert "auto" not in options
    assert options["huawei"] == "华为"
    assert options["cisco"] == "Cisco"
    assert options["h3c"] == "华三"
    assert options["ruijie"] == "锐捷"
    assert options["hillstone"] == "山石"
    assert options["topsec"] == "天融信"
    assert options["dptech"] == "迪普"


def test_frontend_vendor_dropdown_does_not_offer_backend_rejected_huawei_usg_vendor():
    source_options = _select_options("fv")
    target_options = _select_options("tv")

    assert "huawei_usg" not in source_options
    assert "huawei_usg" not in target_options
