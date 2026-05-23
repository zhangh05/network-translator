from __future__ import annotations

import json
from typing import Any

from core.validator.base import ValidationReport


def report_to_json(report: ValidationReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)


def report_to_dict(report: ValidationReport) -> dict[str, Any]:
    return report.to_dict()
