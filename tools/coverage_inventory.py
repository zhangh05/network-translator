#!/usr/bin/env python3
"""
Step 18 · Coverage Inventory
Scans all known features, domains, vendors and reports coverage status.
Outputs:
  docs/coverage/coverage_matrix.json  — machine-readable
  docs/coverage/coverage_matrix.md    — human-readable summary + gaps
"""

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KNOWLEDGE_DIR = ROOT / "knowledge_data"
DOCS_DIR = ROOT / "docs" / "coverage"
TEST_DIR = ROOT / "tests"
BENCH_FILE = ROOT / "tests" / "accuracy" / "translation_cases.json"


# ── 1. Load registry ──────────────────────────────────────────────────────
def load_registry():
    import yaml
    path = KNOWLEDGE_DIR / "features" / "registry.yaml"
    if not path.exists():
        print("ERROR: registry.yaml not found", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        data = yaml.safe_load(f)
    features = data.get("features", {})
    return features


# ── 2. Load domain profiles ───────────────────────────────────────────────
def load_profiles():
    import yaml
    profiles = []
    domains_dir = KNOWLEDGE_DIR / "domains"
    if not domains_dir.exists():
        return profiles
    for domain_dir in sorted(domains_dir.iterdir()):
        if not domain_dir.is_dir():
            continue
        domain = domain_dir.name
        for vendor_dir in sorted(domain_dir.iterdir()):
            if not vendor_dir.is_dir():
                continue
            vendor = vendor_dir.name
            profile_path = vendor_dir / "profile.yaml"
            if not profile_path.exists():
                profiles.append({"domain": domain, "vendor": vendor, "profile_missing": True})
                continue
            try:
                with open(profile_path) as f:
                    profile = yaml.safe_load(f) or {}
            except Exception:
                profiles.append({"domain": domain, "vendor": vendor, "profile_missing": True, "error": str(sys.exc_info()[1])})
                continue
            feats = profile.get("features", {})
            platforms = profile.get("platforms", [])
            profiles.append({
                "domain": domain,
                "vendor": vendor,
                "platforms": platforms,
                "profile_missing": False,
                "features": feats,
            })
    return profiles


# ── 3. Check knowledge .md files ──────────────────────────────────────────
def scan_knowledge_files():
    result = set()
    # New path: domains/{domain}/{vendor}/*.md (exclude profile.yaml)
    domains_dir = KNOWLEDGE_DIR / "domains"
    if domains_dir.exists():
        for domain_dir in domains_dir.iterdir():
            if not domain_dir.is_dir():
                continue
            for vendor_dir in domain_dir.iterdir():
                if not vendor_dir.is_dir():
                    continue
                for f in vendor_dir.iterdir():
                    if f.suffix == ".md":
                        result.add(f"new:{domain_dir.name}/{vendor_dir.name}/{f.stem}")
    # Legacy path: knowledge_data/{vendor}/*.md
    for vendor_dir in KNOWLEDGE_DIR.iterdir():
        if not vendor_dir.is_dir() or vendor_dir.name in ("features", "domains"):
            continue
        for f in vendor_dir.iterdir():
            if f.suffix == ".md":
                result.add(f"legacy:{vendor_dir.name}/{f.stem}")
    return result


def has_knowledge(domain, vendor, feature, known_files):
    new_key = f"new:{domain}/{feature}"
    legacy_key = f"legacy:{vendor}/{feature}"
    return {
        "new_path": new_key in known_files,
        "legacy_path": legacy_key in known_files,
        "any": (new_key in known_files) or (legacy_key in known_files),
    }


# ── 4. Load capability_map ────────────────────────────────────────────────
def load_capability_map():
    import yaml
    path = KNOWLEDGE_DIR / "capability_map.yaml"
    if not path.exists():
        return {}
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return data


# ── 5. Check test coverage ────────────────────────────────────────────────
def scan_tests():
    test_files = list(TEST_DIR.rglob("test_*.py"))
    feature_to_tests = defaultdict(lambda: {"unit": 0, "e2e": 0, "benchmark": 0})
    # Scan unit test files for feature names
    for tf in test_files:
        if "accuracy" in str(tf):
            continue
        text = tf.read_text(encoding="utf-8", errors="replace")
        # Pattern match test functions containing feature names
        test_funcs = re.findall(r'def test_(\w+)', text)
        feat_in_tests = set()
        for func in test_funcs:
            for part in func.split("_"):
                if part:
                    feat_in_tests.add(part)
        for feat in feat_in_tests:
            feature_to_tests[feat]["unit"] += 1
    # Scan benchmark cases
    if BENCH_FILE.exists():
        with open(BENCH_FILE) as f:
            try:
                cases = json.load(f)
            except Exception:
                cases = []
        for case in cases:
            for feat in case.get("features", []):
                pass
            feats_in_config = set()
            config = case.get("config", "")
            for pattern in ["ospf", "bgp", "acl", "nat", "vlan", "interface", "stp", "dhcp",
                            "vrrp", "hsrp", "lldp", "cdp", "qos", "isis", "prefix.list",
                            "route.policy", "route.map", "static.route", "ipsec", "tunnel",
                            "vrf", "bfd", "pbr"]:
                if pattern in config.lower():
                    clean = pattern.replace(".", "_")
                    feats_in_config.add(clean)
            for feat in feats_in_config:
                feature_to_tests[feat]["benchmark"] += 1
    return feature_to_tests


# ── 6. Check analyzer existence ───────────────────────────────────────────
def load_analyzer_modules():
    analyzers_dir = ROOT / "core" / "analyzers"
    available = set()
    if analyzers_dir.exists():
        for f in analyzers_dir.iterdir():
            if f.suffix == ".py" and not f.name.startswith("_"):
                available.add(f.stem)
    return available


# ── 7. Check validator rules ──────────────────────────────────────────────
def has_validator(feature: str) -> str:
    from core.graph.nodes import ValidateNode
    known_validators = {
        "interface": "generic",
        "bgp": "generic",
        "ospf": "generic",
        "acl": "generic",
        "nat": "generic",
        "security_policy": "generic",
    }
    return known_validators.get(feature, "missing")


# ── Main ───────────────────────────────────────────────────────────────────
def main():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    registry = load_registry()
    profiles = load_profiles()
    known_files = scan_knowledge_files()
    cap_map = load_capability_map()
    analyzer_modules = load_analyzer_modules()
    test_coverage = scan_tests()

    # Build a lookup: (domain, vendor) → profile
    profile_lookup = {}
    for p in profiles:
        key = (p["domain"], p["vendor"])
        profile_lookup[key] = p

    rows = []

    for feat_name, feat_meta in registry.items():
        domains = feat_meta.get("domains", [])
        priority = feat_meta.get("priority", "p2")
        risk = feat_meta.get("risk", "low")
        reg_analyzer = feat_meta.get("analyzer", "")

        for domain in domains:
            domain_vendors = [v for v in _vendors_for_domain(domain)]
            for vendor in domain_vendors:
                profile = profile_lookup.get((domain, vendor), {"profile_missing": True})
                profile_support = profile.get("features", {}).get(feat_name) if not profile.get("profile_missing") else None
                if profile_support is None:
                    profile_support = "missing"

                # Capability status: per-vendor from capability_map, or "missing"
                cap_vendor_status = cap_map.get(feat_name, {}).get(vendor, "missing")

                # Knowledge
                kn = has_knowledge(domain, vendor, feat_name, known_files)

                # Analyzer
                if reg_analyzer:
                    analyzer_status = reg_analyzer if reg_analyzer in analyzer_modules else f"{reg_analyzer} (missing module)"
                else:
                    analyzer_status = "noop"

                # Validator
                val_status = has_validator(feat_name)

                # Tests
                tests = {
                    "unit": test_coverage.get(feat_name, {}).get("unit", 0),
                    "e2e": test_coverage.get(feat_name, {}).get("e2e", 0),
                    "benchmark": test_coverage.get(feat_name, {}).get("benchmark", 0),
                }

                row = {
                    "domain": domain,
                    "vendor": vendor,
                    "platforms": profile.get("platforms", []),
                    "feature": feat_name,
                    "priority": priority,
                    "risk": risk,
                    "profile_support": profile_support,
                    "knowledge_new_path": kn["new_path"],
                    "knowledge_legacy_path": kn["legacy_path"],
                    "knowledge_any": kn["any"],
                    "capability_status": cap_vendor_status,
                    "analyzer": analyzer_status,
                    "validator": val_status,
                    "tests": tests,
                    "profile_missing": profile.get("profile_missing", False),
                }
                row["status"] = determine_status(row)
                rows.append(row)

    # Sort: domain → vendor → priority → feature
    priority_order = {"p0": 0, "p1": 1, "p2": 2}
    rows.sort(key=lambda r: (r["domain"], r["vendor"], priority_order.get(r["priority"], 99), r["feature"]))

    # ── Write JSON ─────────────────────────────────────────────────────
    json_path = DOCS_DIR / "coverage_matrix.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    print(f"Wrote {json_path} ({len(rows)} rows)")

    # ── Write MD ───────────────────────────────────────────────────────
    md_path = DOCS_DIR / "coverage_matrix.md"
    _write_md(md_path, rows)
    print(f"Wrote {md_path}")

    # ── Summary ─────────────────────────────────────────────────────────
    _print_summary(rows)
    return 0


def vendors_for_domain(domain):
    from core.domain import DOMAIN_VENDORS
    return DOMAIN_VENDORS.get(domain, [])


def determine_status(row):
    profile_ok = row.get("profile_support") not in ("missing", None)
    cap_ok = row.get("capability_status") not in ("missing", None)
    knowledge_ok = row.get("knowledge_any", False)
    tests_ok = row.get("tests", {}).get("unit", 0) > 0 or row.get("tests", {}).get("benchmark", 0) > 0
    if profile_ok and cap_ok and (knowledge_ok or tests_ok):
        return "covered"
    if profile_ok or cap_ok or knowledge_ok:
        return "partial"
    return "missing"


# (backward compat)
_vendors_for_domain = vendors_for_domain


def _write_md(path, rows):
    total = len(rows)
    covered = sum(1 for r in rows if r["status"] == "covered")
    partial = sum(1 for r in rows if r["status"] == "partial")
    missing = sum(1 for r in rows if r["status"] == "missing")

    p0_missing = [r for r in rows if r["priority"] == "p0" and r["status"] == "missing"]
    high_risk_missing = [r for r in rows if r["risk"] in ("high", "medium") and r["status"] == "missing"]

    lines = []
    lines.append("# Coverage Matrix")
    lines.append("")
    lines.append(f"_Generated by `tools/coverage_inventory.py`_")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total domain×vendor×feature combinations | {total} |")
    lines.append(f"| Covered | {covered} ({covered/max(total,1)*100:.0f}%) |")
    lines.append(f"| Partial | {partial} ({partial/max(total,1)*100:.0f}%) |")
    lines.append(f"| Missing | {missing} ({missing/max(total,1)*100:.0f}%) |")
    lines.append(f"| P0 missing | {len(p0_missing)} |")
    lines.append(f"| High/medium risk missing | {len(high_risk_missing)} |")
    lines.append("")

    if p0_missing:
        lines.append("## P0 Gaps")
        lines.append("")
        lines.append("| Domain | Vendor | Feature | Profile | Knowledge | Capability | Analyzer |")
        lines.append("|--------|--------|---------|---------|-----------|------------|----------|")
        for r in p0_missing:
            kn = "Y" if r["knowledge_any"] else "N"
            cap = r["capability_status"]
            prof = r["profile_support"]
            an = r["analyzer"]
            lines.append(f"| {r['domain']} | {r['vendor']} | {r['feature']} | {prof} | {kn} | {cap} | {an} |")
        lines.append("")

    if high_risk_missing:
        lines.append("## High-risk Gaps")
        lines.append("")
        lines.append("| Domain | Vendor | Feature | Priority | Profile | Knowledge | Capability |")
        lines.append("|--------|--------|---------|----------|---------|-----------|------------|")
        for r in high_risk_missing:
            kn = "Y" if r["knowledge_any"] else "N"
            cap = r["capability_status"]
            prof = r["profile_support"]
            lines.append(f"| {r['domain']} | {r['vendor']} | {r['feature']} | {r['priority']} | {prof} | {kn} | {cap} |")
        lines.append("")

    # By domain
    lines.append("## By Domain")
    lines.append("")
    for domain in ["routing", "switching", "firewall"]:
        domain_rows = [r for r in rows if r["domain"] == domain]
        d_covered = sum(1 for r in domain_rows if r["status"] == "covered")
        d_partial = sum(1 for r in domain_rows if r["status"] == "partial")
        d_missing = sum(1 for r in domain_rows if r["status"] == "missing")
        lines.append(f"### {domain}")
        lines.append("")
        lines.append(f"Coverage: {d_covered}/{len(domain_rows)} ({d_covered/max(len(domain_rows),1)*100:.0f}%) — "
                     f"{d_partial} partial, {d_missing} missing")
        lines.append("")
        lines.append("| Vendor | Feature | Status | Profile | Knowledge | Capability | Priority | Risk |")
        lines.append("|--------|---------|--------|---------|-----------|------------|----------|------|")
        for r in domain_rows:
            status_icon = {"covered": "✅", "partial": "🟡", "missing": "❌"}.get(r["status"], "❓")
            kn = ("✅" if r["knowledge_any"] else "❌")
            prof = r["profile_support"]
            cap = r["capability_status"]
            lines.append(f"| {r['vendor']} | {r['feature']} | {status_icon} {r['status']} | {prof} | {kn} | {cap} | "
                         f"{r['priority']} | {r['risk']} |")
        lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _print_summary(rows):
    total = len(rows)
    covered = sum(1 for r in rows if r["status"] == "covered")
    partial = sum(1 for r in rows if r["status"] == "partial")
    missing = sum(1 for r in rows if r["status"] == "missing")

    p0 = [r for r in rows if r["priority"] == "p0"]
    p0_cov = sum(1 for r in p0 if r["status"] in ("covered", "partial"))
    high_risk = [r for r in rows if r["risk"] == "high"]
    hr_cov = sum(1 for r in high_risk if r["status"] == "covered")

    print(f"\n{'='*60}")
    print(f"  Coverage Summary")
    print(f"{'='*60}")
    print(f"  Total combinations : {total}")
    print(f"  Covered            : {covered} ({covered/max(total,1)*100:.0f}%)")
    print(f"  Partial            : {partial} ({partial/max(total,1)*100:.0f}%)")
    print(f"  Missing            : {missing} ({missing/max(total,1)*100:.0f}%)")
    print(f"  P0 coverage        : {p0_cov}/{len(p0)} ({p0_cov/max(len(p0),1)*100:.0f}%)")
    print(f"  High risk covered  : {hr_cov}/{len(high_risk)} ({hr_cov/max(len(high_risk),1)*100:.0f}%)")
    print(f"{'='*60}")


if __name__ == "__main__":
    sys.exit(main())
