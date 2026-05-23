from pathlib import Path
import shutil
import subprocess

import pytest


def test_frontend_index_javascript_is_syntax_valid():
    node = shutil.which("node")
    if not node:
        pytest.skip("node executable is not available")

    html = Path("frontend/index.html").read_text(encoding="utf-8")
    start = html.index("<script>") + len("<script>")
    end = html.index("</script>", start)
    script = html[start:end]

    result = subprocess.run(
        [node, "--check", "-"],
        input=script,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_copy_menu_is_not_clipped_by_result_card():
    html = Path("frontend/index.html").read_text(encoding="utf-8")

    assert '#rcard{overflow:visible}' in html
    assert ".cp-menu{display:none;position:absolute;top:100%;right:0;" in html
    assert 'data-cp="all"' in html
    assert 'data-cp="deployable"' in html
    assert 'data-cp="report"' in html


def test_copy_uses_clipboard_fallback():
    html = Path("frontend/index.html").read_text(encoding="utf-8")

    assert "async function _copyText" in html
    assert "navigator.clipboard.writeText" in html
    assert "document.execCommand(\"copy\")" in html
    assert "await _copyText(t)" in html
    assert html.count("async function _copyAll") == 1


def test_sidebar_project_rename_controls_exist():
    html = Path("frontend/index.html").read_text(encoding="utf-8")

    assert "function startRenameProject" in html
    assert "function commitRenameProject" in html
    assert "rename-input" in html
    assert "data-rename" in html
    assert "dblclick" in html
