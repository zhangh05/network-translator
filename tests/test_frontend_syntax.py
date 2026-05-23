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
