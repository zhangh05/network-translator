"""P0-3: VERSION file reading tests."""

import sys
from pathlib import Path


def test_version_file_exists_and_valid():
    root = Path(__file__).parent.parent
    version_file = root / "VERSION"
    assert version_file.exists(), "VERSION file must exist"
    content = version_file.read_text().strip()
    assert len(content) > 0, "VERSION file must not be empty"


def _read_version_safe():
    """Copy of the web_app._read_version logic."""
    root = Path(__file__).parent.parent
    try:
        return (root / "VERSION").read_text().strip()
    except Exception:
        return "unknown"


def test_version_reader_logic():
    root = Path(__file__).parent.parent
    version_path = root / "VERSION"
    expected = version_path.read_text().strip()
    version = _read_version_safe()
    assert version == expected
    assert version != "unknown"
