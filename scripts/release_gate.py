# -*- coding: utf-8 -*-
"""Release gate checks for translator service."""

import json
import subprocess
import sys
from pathlib import Path


def run(cmd):
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, check=False)


def check_benchmark(path: Path) -> bool:
    if not path.exists():
        print("benchmark file missing")
        return False
    data = json.loads(path.read_text(encoding="utf-8"))
    score = data.get("TranslationQualityScore", {}).get("avg_score", 0)
    print(f"benchmark avg_score={score}")
    return score >= 92


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    ok = True

    py = sys.executable or "python3"
    ok = ok and run([py, "-m", "pytest", "-q"]).returncode == 0
    ok = ok and run([py, "tools/knowledge_lint.py"]).returncode == 0
    ok = ok and check_benchmark(root / "bench" / "harness_results.json")

    if ok:
        print("RELEASE_GATE_OK")
        return 0
    print("RELEASE_GATE_FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
