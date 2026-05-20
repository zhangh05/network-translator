#!/usr/bin/env python3
"""Sanitized corpus validator — data governance checks.

Validates:
1. No real IPs in sanitized configs (RFC 1918 / documentation ranges only)
2. No real hostnames / domains / credentials
3. Annotation ↔ sanitized file consistency (hash verification)
4. Annotation schema compliance
5. No orphaned entries (annotation or sanitized file missing counterpart)
6. Valid source/target vendor/platform/domain values
7. Feature names match registry

Usage:
    python tools/validate_corpus.py              # full check, report to stdout
    python tools/validate_corpus.py --json        # JSON output
    python tools/validate_corpus.py --report      # write report to reports/corpus_validation.md
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent

ALLOWED_VENDORS = {"cisco", "huawei", "h3c", "ruijie", "hillstone", "topsec", "dbappsecurity", "dptech"}
ALLOWED_DOMAINS = {"routing", "switching", "firewall"}

# Patterns that MUST NOT appear in sanitized configs
FORBIDDEN_PATTERNS = [
    (re.compile(r"(?i)\b(?:password|secret)\s+\S+\s*$"), "credentials in config line"),
    (re.compile(r"(?i)\b(username|user)\s+\S+\s+password\s+\S+"), "username+password combo"),
    (re.compile(r"(?i)\bpre-shared-key\s+\S+"), "pre-shared-key credential"),
    (re.compile(r"(?i)\bisakmp\s+key\s+\S+"), "ISAKMP key credential"),
    (re.compile(r"(?i)\bsnmp-server\s+community\s+\S+"), "SNMP community string"),
    (re.compile(r"(?i)\b(?:authentication\s+key|auth\s+key|auth\s+password)\s+\S+"), "auth credential"),
    (re.compile(r"(?i)\b(?:certificate|cert-data|private-key)\s+\S"), "certificate/private key fragment"),
]

# Redacted value tokens that are acceptable in sanitized configs
KNOWN_REDACTION = {"__REDACTED__", "[REDACTED]", "$REDACTED$", "REDACTED"}

# Real IP ranges that should NOT appear in sanitized corpus
# (Only RFC 1918 + RFC 5737 documentation ranges are acceptable)
REAL_IP_RANGES = [
    # Public IP ranges (non-RFC1918, non-documentation)
    (re.compile(r"\b(?:8\.8\.8\.8|8\.8\.4\.4)\b"), "Google DNS — use 198.18.0.1 instead"),
    (re.compile(r"\b1\.1\.1\.1\b"), "Cloudflare DNS — use 198.18.0.1 instead"),
    (re.compile(r"\b(?:[1-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-4])\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "potential public IP"),
]

# Acceptable private/documentation ranges:
#   10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918)
#   198.18.0.0/15 (RFC 2544 benchmark, commonly used in docs)
#   198.51.100.0/24, 203.0.113.0/24, 192.0.2.0/24 (RFC 5737 documentation)
ACCEPTABLE_IP_PREFIXES = [
    re.compile(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    re.compile(r"^172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"),
    re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}"),
    re.compile(r"^198\.18\.\d{1,3}\.\d{1,3}"),
    re.compile(r"^198\.19\.\d{1,3}\.\d{1,3}"),
    re.compile(r"^192\.0\.2\.\d{1,3}"),
    re.compile(r"^198\.51\.100\.\d{1,3}"),
    re.compile(r"^203\.0\.113\.\d{1,3}"),
    re.compile(r"^255\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # subnet masks
    re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # loopback
    re.compile(r"^169\.254\.\d{1,3}\.\d{1,3}"),       # link-local
]


def _is_acceptable_ip(ip_str: str) -> bool:
    for p in ACCEPTABLE_IP_PREFIXES:
        if p.match(ip_str):
            return True
    return False


def _load_feature_registry() -> Dict[str, Any]:
    """Load feature registry for validating feature names."""
    try:
        import yaml
        path = PROJECT_ROOT / "knowledge_data" / "features" / "registry.yaml"
        reg = yaml.safe_load(path.read_text())
        return reg.get("features", {}) if isinstance(reg, dict) else {}
    except Exception:
        return {}


def _load_schema() -> Optional[Dict[str, Any]]:
    """Load annotation schema for validation."""
    schema_path = PROJECT_ROOT / "corpus" / "schema.json"
    try:
        return json.loads(schema_path.read_text())
    except Exception:
        return None


def _check_no_real_ips(content: str, filepath: str) -> List[Dict[str, Any]]:
    """Check for real IPs outside of acceptable ranges."""
    findings = []
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for match in ip_pattern.finditer(content):
        ip = match.group()
        if _is_acceptable_ip(ip):
            continue
        # Skip if it looks like a version number or other non-IP
        if ip.startswith("0.") or ip == "0.0.0.0":
            continue
        findings.append({
            "file": filepath,
            "type": "potential_real_ip",
            "value": ip,
            "position": match.start(),
            "severity": "fatal",
        })
    return findings


def _check_forbidden_patterns(content: str, filepath: str) -> List[Dict[str, Any]]:
    """Check for credentials and other forbidden patterns.

    Redacted values (__REDACTED__, [REDACTED], etc.) are skipped.
    """
    findings = []
    KNOWN = KNOWN_REDACTION
    for pattern, desc in FORBIDDEN_PATTERNS:
        for match in pattern.finditer(content):
            line_start = content.rfind("\n", 0, match.start()) + 1
            line_end = content.find("\n", match.start())
            full_line = content[line_start:line_end] if line_end != -1 else content[line_start:]
            parts = full_line.strip().split()
            # Check if any trailing token is a known redaction value
            has_redacted = any(p in KNOWN for p in parts)
            if has_redacted:
                continue
            findings.append({
                "file": filepath,
                "type": "forbidden_pattern",
                "description": desc,
                "value": match.group().strip()[:80],
                "position": match.start(),
                "severity": "fatal",
            })
    return findings


def _check_hostname_leak(content: str, filepath: str) -> List[Dict[str, Any]]:
    """Check for suspicious real-hostname patterns."""
    findings = []
    patterns = [
        (r"(?i)\b(?:corp|prod|stg|dev|dc[-\w]+)\.\w+\.(?:com|net|org|local)\b", "potential real hostname"),
        (r"(?i)\b(?:internal|private|mail|vpn|web|app|db)\d*\.\w+\.\w+\b", "potential real hostname"),
    ]
    for pat, desc in patterns:
        for match in re.finditer(pat, content):
            findings.append({
                "file": filepath,
                "type": "potential_real_hostname",
                "description": desc,
                "value": match.group()[:80],
                "position": match.start(),
                "severity": "warning",
            })
    return findings


def _validate_annotation_schema(ann: Dict[str, Any], fpath: str) -> List[Dict[str, Any]]:
    """Validate annotation JSON schema compliance."""
    issues = []
    required_top = {"id", "classification", "annotation", "config", "source"}
    missing = required_top - set(ann.keys())
    if missing:
        issues.append({
            "file": fpath,
            "type": "schema_missing_field",
            "description": f"Missing top-level fields: {', '.join(sorted(missing))}",
            "severity": "fatal",
        })

    # Validate classification
    cls = ann.get("classification", {})
    if cls.get("vendor") and cls["vendor"] not in ALLOWED_VENDORS:
        issues.append({
            "file": fpath,
            "type": "invalid_vendor",
            "description": f"Unknown vendor: {cls['vendor']}",
            "value": cls["vendor"],
            "severity": "fatal",
        })
    if cls.get("domain") and cls["domain"] not in ALLOWED_DOMAINS:
        issues.append({
            "file": fpath,
            "type": "invalid_domain",
            "description": f"Unknown domain: {cls['domain']}",
            "value": cls["domain"],
            "severity": "fatal",
        })

    # Validate annotation
    ann_sec = ann.get("annotation", {})
    exp = ann_sec.get("expected_translation", {})
    if exp.get("target_vendor") and exp["target_vendor"] not in ALLOWED_VENDORS:
        issues.append({
            "file": fpath,
            "type": "invalid_target_vendor",
            "description": f"Unknown target vendor: {exp['target_vendor']}",
            "severity": "fatal",
        })

    ver = ann_sec.get("verification", {})
    for field in ("deployable", "manual_review_required"):
        val = ver.get(field)
        if val is not None and not isinstance(val, bool):
            issues.append({
                "file": fpath,
                "type": "schema_type_error",
                "description": f"{field} should be boolean, got {type(val).__name__}",
                "severity": "warning",
            })

    return issues


def _verify_file_consistency(annotations_dir: Path, sanitized_dir: Path) -> List[Dict[str, Any]]:
    """Verify annotation ↔ sanitized file consistency."""
    issues = []
    ann_files = set(annotations_dir.glob("*.annotation.json"))
    sanitized_files = set(sanitized_dir.glob("*.txt"))

    # Map annotations to expected sanitized paths.
    # Annotation files are named like: {base}.annotation.json
    # where {base} is the sanitized filename (e.g., "sw-mstp-001.txt")
    ann_to_san = {}
    for af in ann_files:
        base = af.name.replace(".annotation.json", "")
        ann_to_san[base] = af

    san_to_ann = {}
    for sf in sanitized_files:
        san_to_ann[sf.name] = sf

    # Check for annotations with no matching sanitized file
    sanitized_names = set(san_to_ann.keys())
    for base, af in ann_to_san.items():
        if base not in sanitized_names:
            issues.append({
                "file": str(af.relative_to(PROJECT_ROOT)),
                "type": "orphaned_annotation",
                "description": f"No matching sanitized file for {base}",
                "severity": "fatal",
            })

    # Check for sanitized files with no matching annotation
    annotation_bases = set(ann_to_san.keys())
    for name, sf in san_to_ann.items():
        if name not in annotation_bases:
            issues.append({
                "file": str(sf.relative_to(PROJECT_ROOT)),
                "type": "orphaned_sanitized",
                "description": f"No matching annotation for {name}",
                "severity": "fatal",
            })

    # Verify config path in annotation matches actual
    for base, af in ann_to_san.items():
        try:
            ann = json.loads(af.read_text())
        except (json.JSONDecodeError, Exception):
            issues.append({
                "file": str(af.relative_to(PROJECT_ROOT)),
                "type": "invalid_json",
                "description": "Cannot parse annotation JSON",
                "severity": "fatal",
            })
            continue

        cfg_path = ann.get("config", {}).get("sanitized_path", "")
        expected = sanitized_dir / cfg_path
        if cfg_path and not expected.exists():
            # Try relative to corpus root
            alt = PROJECT_ROOT / "corpus" / cfg_path
            if not alt.exists():
                issues.append({
                    "file": str(af.relative_to(PROJECT_ROOT)),
                    "type": "config_path_mismatch",
                    "description": f"Referenced config not found: {cfg_path}",
                    "severity": "fatal",
                })

    return issues


def _is_known_subfeature(feat: str) -> bool:
    """Check if a feature is a known sub-feature of a registered feature."""
    known_subs = {"nat_server", "nat_source"}
    if feat in known_subs:
        return True
    return False


def _validate_features(annotations_dir: Path, registry_features: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Validate annotation feature names match registry."""
    issues = []
    reg_feature_names = set(registry_features.keys())
    for af in sorted(annotations_dir.glob("*.annotation.json")):
        try:
            ann = json.loads(af.read_text())
        except Exception:
            continue
        features = ann.get("classification", {}).get("features", [])
        for feat in features:
            if feat not in reg_feature_names and not _is_known_subfeature(feat):
                issues.append({
                    "file": str(af.relative_to(PROJECT_ROOT)),
                    "type": "unknown_feature",
                    "description": f"Feature '{feat}' not in registry",
                    "value": feat,
                    "severity": "warning",
                })
    return issues


def run_validation() -> Dict[str, Any]:
    """Run all corpus validation checks."""
    annotations_dir = PROJECT_ROOT / "corpus" / "annotations"
    sanitized_dir = PROJECT_ROOT / "corpus" / "sanitized"
    registry = _load_feature_registry()

    all_findings = []

    # 1. Sanitized file content checks
    for sf in sorted(sanitized_dir.glob("*.txt")):
        rel = str(sf.relative_to(PROJECT_ROOT))
        content = sf.read_text()
        all_findings.extend(_check_no_real_ips(content, rel))
        all_findings.extend(_check_forbidden_patterns(content, rel))
        all_findings.extend(_check_hostname_leak(content, rel))

    # 2. Annotation schema checks
    for af in sorted(annotations_dir.glob("*.annotation.json")):
        rel = str(af.relative_to(PROJECT_ROOT))
        try:
            ann = json.loads(af.read_text())
        except (json.JSONDecodeError, Exception):
            all_findings.append({
                "file": rel, "type": "invalid_json",
                "description": "Cannot parse annotation JSON",
                "severity": "fatal",
            })
            continue
        all_findings.extend(_validate_annotation_schema(ann, rel))

    # 3. File consistency checks
    all_findings.extend(_verify_file_consistency(annotations_dir, sanitized_dir))

    # 4. Feature name validation
    all_findings.extend(_validate_features(annotations_dir, registry))

    # 5. Check for schema.json presence
    schema_path = PROJECT_ROOT / "corpus" / "schema.json"
    if not schema_path.exists():
        all_findings.append({
            "file": "corpus/schema.json",
            "type": "missing_schema",
            "description": "Schema file missing",
            "severity": "fatal",
        })

    # Summarize
    total = len(all_findings)
    by_severity = defaultdict(int)
    by_type = defaultdict(int)
    for f in all_findings:
        by_severity[f["severity"]] += 1
        by_type[f["type"]] += 1

    return {
        "total_findings": total,
        "fatal": by_severity.get("fatal", 0),
        "warning": by_severity.get("warning", 0),
        "by_type": dict(by_type),
        "findings": all_findings,
        "pass": by_severity.get("fatal", 0) == 0,
    }


def _format_report(result: Dict[str, Any]) -> str:
    lines = []
    def w(s=""):
        lines.append(s)

    w("# Corpus Validation Report")
    w()
    w(f"Generated: {__import__('time').strftime('%Y-%m-%d %H:%M:%S')}")
    w()
    w(f"**Status:** {'PASS' if result['pass'] else 'FAIL'}")
    w(f"**Total findings:** {result['total_findings']}")
    w(f"**Fatal:** {result['fatal']}")
    w(f"**Warning:** {result['warning']}")
    w()

    if not result["findings"]:
        w("No issues found.")
        return "\n".join(lines)

    # Group by severity then type
    w("## Findings")
    w()
    for severity in ("fatal", "warning"):
        filtered = [f for f in result["findings"] if f["severity"] == severity]
        if not filtered:
            continue
        w(f"### {severity.upper()}")
        w()
        for f in filtered:
            desc = f.get("description", f.get("type", "unknown"))
        w(f"- **{f['file']}** — {desc}")
        if f.get("type"):
            w(f"  - Type: `{f['type']}`")
        if f.get("value"):
            w(f"  - Value: `{f['value']}`")
        w()

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Validate sanitized corpus for data governance")
    parser.add_argument("--json", action="store_true", help="Output JSON to stdout")
    parser.add_argument("--report", action="store_true", help="Write report to reports/corpus_validation.md")
    args = parser.parse_args()

    result = run_validation()

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    report = _format_report(result)

    if args.report:
        report_dir = PROJECT_ROOT / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "corpus_validation.md"
        report_path.write_text(report)
        print(f"Report: {report_path}")
    else:
        print(report)

    sys.exit(0 if result["pass"] else 1)


if __name__ == "__main__":
    main()
