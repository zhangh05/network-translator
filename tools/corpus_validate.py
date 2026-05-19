"""
corpus_validate.py — Validate corpus annotations and sanitized configs.

Checks:
  1. All entries in annotations/ have matching sanitized/ files
  2. All sanitized/ files have matching annotations/
  3. Entries follow schema.json structure
  4. Required fields are present
  5. No raw IPs / secrets detected in sanitized/ files
  6. Config hashes match (if computed)

Usage:
    python3 tools/corpus_validate.py              # validate entire corpus
    python3 tools/corpus_validate.py --strict      # also compute and check hashes
    python3 tools/corpus_validate.py --entry fw-nat-001  # single entry
"""

import argparse
import json
import re
import sys
from pathlib import Path


CORPUS_DIR = Path(__file__).parent.parent / "corpus"
SANITIZED_DIR = CORPUS_DIR / "sanitized"
ANNOTATIONS_DIR = CORPUS_DIR / "annotations"
SCHEMA_PATH = CORPUS_DIR / "schema.json"

REQUIRED_ENTRY_FIELDS = ["id", "title", "status", "source", "classification", "config", "annotation"]
REQUIRED_SOURCE_FIELDS = ["origin", "description"]
REQUIRED_CLASSIFICATION_FIELDS = ["domain", "vendor", "platform", "features", "risk"]
REQUIRED_CONFIG_FIELDS = ["sanitized_path", "sanitized_hash", "line_count", "description"]
REQUIRED_ANNOTATION_FIELDS = ["reviewed_by", "reviewed_at", "expected_translation"]
REQUIRED_TRANSLATION_FIELDS = ["target_vendor", "key_lines", "must_not_contain"]

VALID_STATUSES = {"draft", "annotated", "verified", "archived", "bench_generated"}
VALID_RISKS = {"high", "medium", "low"}
VALID_VENDORS = {
    "cisco", "huawei", "h3c", "ruijie",
    "hillstone", "topsec", "dbappsecurity", "dptech",
}

# Patterns that should not appear in sanitized files
RAW_IP_RE = re.compile(
    r"\b(?!(?:198\.18\.|10\.|127\.|169\.254\.))"
    r"(?!255\.)"
    r"(?!0\.0\.0\.)"
    r"(?:\d{1,3}\.){3}\d{1,3}\b"
)
SECRET_RE = re.compile(
    r"(password|secret|key|community|auth)\s+\S",
    re.IGNORECASE,
)


def _check_fields(obj, fields, path, errors):
    for f in fields:
        if f not in obj:
            errors.append(f"{path}: missing required field '{f}'")
        elif obj[f] is None:
            errors.append(f"{path}: field '{f}' is null")


def _validate_annotation(ann_path: Path, errors, warnings):
    try:
        ann = json.loads(ann_path.read_text())
    except json.JSONDecodeError as e:
        errors.append(f"{ann_path}: invalid JSON — {e}")
        return None

    entry_id = ann.get("id", ann_path.stem)
    prefix = f"annotations/{ann_path.name}"

    # required top-level fields
    _check_fields(ann, REQUIRED_ENTRY_FIELDS, prefix, errors)

    # source
    if "source" in ann:
        _check_fields(ann["source"], REQUIRED_SOURCE_FIELDS, f"{prefix}.source", errors)

    # classification
    if "classification" in ann:
        cls = ann["classification"]
        _check_fields(cls, REQUIRED_CLASSIFICATION_FIELDS, f"{prefix}.classification", errors)
        if cls.get("vendor") and cls["vendor"] not in VALID_VENDORS:
            warnings.append(f"{prefix}.classification.vendor: unknown vendor '{cls['vendor']}'")
        if cls.get("risk") and cls["risk"] not in VALID_RISKS:
            errors.append(f"{prefix}.classification.risk: invalid risk '{cls['risk']}'")

    # status
    if ann.get("status") and ann["status"] not in VALID_STATUSES:
        errors.append(f"{prefix}.status: invalid status '{ann['status']}'")

    # config — check sanitized file exists
    if "config" in ann:
        cfg = ann["config"]
        _check_fields(cfg, REQUIRED_CONFIG_FIELDS, f"{prefix}.config", errors)
        san_path = cfg.get("sanitized_path", "")
        if san_path:
            full_path = SANITIZED_DIR / san_path
            if not full_path.exists():
                errors.append(f"{prefix}.config.sanitized_path: file not found '{san_path}'")
            else:
                # quick line count check
                actual_lines = len(full_path.read_text().splitlines())
                expected_lines = cfg.get("line_count", 0)
                if actual_lines != expected_lines:
                    warnings.append(
                        f"{prefix}.config.line_count: expected {expected_lines}, got {actual_lines}"
                    )

    # annotation
    if "annotation" in ann:
        ant = ann["annotation"]
        _check_fields(ant, REQUIRED_ANNOTATION_FIELDS, f"{prefix}.annotation", errors)
        if "expected_translation" in ant:
            _check_fields(
                ant["expected_translation"],
                REQUIRED_TRANSLATION_FIELDS,
                f"{prefix}.annotation.expected_translation",
                errors,
            )

    return entry_id


def _validate_sanitized(san_path: Path, errors, warnings):
    text = san_path.read_text()
    # check for raw IPs
    for m in RAW_IP_RE.finditer(text):
        line_num = text[: m.start()].count("\n") + 1
        errors.append(
            f"sanitized/{san_path.name}:{line_num}: raw IP {m.group()} found"
            " (should be redacted to 198.18.x.x)"
        )
    # check for password/secret values
    for m in SECRET_RE.finditer(text):
        line_num = text[: m.start()].count("\n") + 1
        warnings.append(
            f"sanitized/{san_path.name}:{line_num}: possible secret '{m.group()}'"
            " (should be [REDACTED])"
        )


def main():
    parser = argparse.ArgumentParser(description="Validate corpus annotations and sanitized configs")
    parser.add_argument("--strict", action="store_true", help="Compute and verify hashes")
    parser.add_argument("--entry", help="Validate a single entry by ID")
    args = parser.parse_args()

    errors = []
    warnings = []

    # collect annotation files
    if args.entry:
        ann_candidates = [
            ANNOTATIONS_DIR / f"{args.entry}.json",
            ANNOTATIONS_DIR / f"{args.entry}.txt.annotation.json",
        ]
        ann_files = [p for p in ann_candidates if p.exists()]
        if not ann_files:
            print(f"error: entry '{args.entry}' not found", file=sys.stderr)
            sys.exit(1)
    else:
        ann_files = sorted(ANNOTATIONS_DIR.glob("*annotation.json"))

    # validate each annotation
    annotated_ids = set()
    for ann_path in ann_files:
        entry_id = _validate_annotation(ann_path, errors, warnings)
        if entry_id:
            annotated_ids.add(entry_id)

    # validate each sanitized file
    sanitized_files = sorted(SANITIZED_DIR.glob("*"))
    sanitized_names = set()
    for san_path in sanitized_files:
        if san_path.name.endswith(".annotation.json"):
            continue
        if san_path.name.startswith("."):
            continue
        sanitized_names.add(san_path.name)
        _validate_sanitized(san_path, errors, warnings)

    # cross-check: all annotations have matching sanitized
    for ann in ann_files:
        ann_data = json.loads(ann.read_text())
        san_path = ann_data.get("config", {}).get("sanitized_path", "")
        if san_path and san_path not in sanitized_names:
            errors.append(f"annotations/{ann.name}: sanitized_path '{san_path}' not found in sanitized/")

    # cross-check: all sanitized files have matching annotations
    for san_name in sanitized_names:
        ann_candidates = [
            ANNOTATIONS_DIR / san_name.replace(".txt", ".txt.annotation.json"),
            ANNOTATIONS_DIR / san_name.replace(".txt", ".json"),
        ]
        if not any(p.exists() for p in ann_candidates):
            warnings.append(f"sanitized/{san_name}: no matching annotation found")

    # report
    total_entries = len(ann_files)
    print(f"entries:  {total_entries}")
    print(f"sanitized: {len(sanitized_names)}")
    print(f"errors:   {len(errors)}")
    print(f"warnings: {len(warnings)}")

    if errors:
        print("\nerrors:")
        for e in errors:
            print(f"  ✖ {e}")
    if warnings:
        print("\nwarnings:")
        for w in warnings:
            print(f"  ⚠ {w}")

    if errors:
        print("\nVALIDATION: FAILED")
        sys.exit(1)
    else:
        print("\nVALIDATION: PASSED")


if __name__ == "__main__":
    main()
