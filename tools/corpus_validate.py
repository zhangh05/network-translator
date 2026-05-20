#!/usr/bin/env python3
"""
corpus_validate.py — DEPRECATED. Use tools/validate_corpus.py instead.

This wrapper delegates to validate_corpus.py for backward compatibility.
It will be removed in a future release.
"""

import sys
import warnings
from pathlib import Path


def main():
    print("[DEPRECATED] tools/corpus_validate.py is deprecated. Use 'python tools/validate_corpus.py' instead.", file=sys.stderr)

    validate_path = Path(__file__).resolve().parent / "validate_corpus.py"
    if not validate_path.exists():
        print("ERROR: validate_corpus.py not found alongside corpus_validate.py", file=sys.stderr)
        sys.exit(1)

    import runpy
    sys.argv[0] = str(validate_path)
    try:
        runpy.run_path(str(validate_path), run_name="__main__")
    except SystemExit:
        pass
    except Exception as e:
        print(f"ERROR: delegation failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
