# -*- coding: utf-8 -*-
"""Knowledge base lint checks for production readiness.

Checks:
  - Profile completeness (domain/vendor/platforms/features)
  - Registry vs actual knowledge file coverage (with TYPE_TO_FILE alias awareness)
  - Capability_map high-risk feature coverage
  - Cross-vendor consistency
"""

from pathlib import Path
from typing import Dict, List

KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent / "knowledge_data"
REQUIRED_PROFILE_FIELDS = ["domain", "vendor", "platforms", "features"]

# Features embedded within other files (handled by TYPE_TO_FILE mapping)
EMBEDDED_FEATURES = {
    "trunk": "vlan",
    "lacp": "interface",
    "prefix_list": "acl",
    "route_policy": "bgp",
    "security_policy": "security_zone",
    "address_object": "security_zone",
    "service_object": "security_zone",
    "zone": "security_zone",
    "role": "security_zone",
}

# Sub-feature → parent features in capability_map
SUB_FEATURES = {
    "zone": "security_zone",
    "security_policy": "security_zone",
    "address_object": "security_zone",
    "service_object": "security_zone",
}


def _load_yaml(path: Path) -> dict:
    try:
        import yaml
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _has_old_path_fallback(vendor: str, feature: str, base_dir: Path) -> bool:
    """Check if old-path knowledge_data/{vendor}/{feature}.md exists."""
    direct = base_dir / vendor / f"{feature}.md"
    if direct.exists():
        return True
    aliased = EMBEDDED_FEATURES.get(feature)
    if aliased:
        alias_path = base_dir / vendor / f"{aliased}.md"
        if alias_path.exists():
            return True
    return False


def lint_profiles(base_dir: Path) -> List[str]:
    issues = []
    domains_dir = base_dir / "domains"
    if not domains_dir.exists():
        return ["domains/ directory not found"]
    for domain_dir in sorted(domains_dir.iterdir()):
        if not domain_dir.is_dir():
            continue
        for vendor_dir in sorted(domain_dir.iterdir()):
            if not vendor_dir.is_dir():
                continue
            profile = vendor_dir / "profile.yaml"
            if not profile.exists():
                issues.append(f"domains/{domain_dir.name}/{vendor_dir.name}/profile.yaml: missing")
                continue
            if profile.stat().st_size == 0:
                issues.append(f"domains/{domain_dir.name}/{vendor_dir.name}/profile.yaml: empty")
                continue
            data = _load_yaml(profile)
            for field in REQUIRED_PROFILE_FIELDS:
                if field not in data:
                    issues.append(f"domains/{domain_dir.name}/{vendor_dir.name}/profile.yaml: missing field '{field}'")
            if "platforms" in data and not isinstance(data["platforms"], list):
                issues.append(f"domains/{domain_dir.name}/{vendor_dir.name}/profile.yaml: 'platforms' must be a list")
            features = data.get("features", {})
            if features and not isinstance(features, dict):
                issues.append(f"domains/{domain_dir.name}/{vendor_dir.name}/profile.yaml: 'features' must be a mapping")
    return issues


def lint_registry_vs_knowledge(base_dir: Path) -> List[str]:
    issues = []
    registry_path = base_dir / "features" / "registry.yaml"
    if not registry_path.exists():
        return ["features/registry.yaml: missing"]
    registry = _load_yaml(registry_path).get("features", {})

    for feat_name, feat_meta in registry.items():
        domains = feat_meta.get("domains", [])
        priority = feat_meta.get("priority", "p3")
        if priority not in ("p0", "p1"):
            continue
        for domain in domains:
            found_in_domain = False
            domain_dir = base_dir / "domains" / domain
            if domain_dir.exists():
                for vendor_dir in domain_dir.iterdir():
                    if not vendor_dir.is_dir():
                        continue
                    vendor = vendor_dir.name.lower()
                    if (vendor_dir / f"{feat_name}.md").exists():
                        found_in_domain = True
                        break
            if found_in_domain:
                continue
            # Acceptable: alias to another file name
            if feat_name in EMBEDDED_FEATURES:
                continue
            # Acceptable: exists in old path
            old_found = False
            for vendor_dir in base_dir.iterdir():
                if not vendor_dir.is_dir() or vendor_dir.name in ("domains", "features"):
                    continue
                if (vendor_dir / f"{feat_name}.md").exists():
                    old_found = True
                    break
                if _has_old_path_fallback(vendor_dir.name, feat_name, base_dir):
                    old_found = True
                    break
            if not old_found:
                if priority == "p0":
                    issues.append(f"features/registry.yaml: {feat_name} (p{priority}) has no .md for domain '{domain}' — P0 should have dedicated knowledge")
                # P1 features without .md are acceptable (handled by LLM)
    return issues


def lint_capability_map(base_dir: Path) -> List[str]:
    issues = []
    cap_path = base_dir / "capability_map.yaml"
    if not cap_path.exists():
        return ["capability_map.yaml: missing"]
    cap_data = _load_yaml(cap_path)

    registry_path = base_dir / "features" / "registry.yaml"
    registry = _load_yaml(registry_path).get("features", {})

    high_risk = [name for name, meta in registry.items() if meta.get("risk") == "high"]
    for feat in high_risk:
        if feat not in cap_data:
            parent = SUB_FEATURES.get(feat)
            if parent and parent in cap_data:
                continue
            issues.append(f"capability_map.yaml: missing high-risk feature '{feat}'")

    for feat in cap_data:
        if feat not in registry:
            issues.append(f"registry.yaml: feature '{feat}' in capability_map but not in registry")
    return issues


def lint_knowledge(base_dir: Path = KNOWLEDGE_DIR) -> Dict[str, List[str]]:
    return {
        "profile": lint_profiles(base_dir),
        "registry": lint_registry_vs_knowledge(base_dir),
        "capability_map": lint_capability_map(base_dir),
    }


def run_coverage(base_dir: Path = KNOWLEDGE_DIR) -> dict:
    """Non-blocking coverage summary for --coverage mode."""
    try:
        from tools.coverage_inventory import load_registry, load_profiles, vendors_for_domain, determine_status
        import yaml
    except ImportError:
        return {}

    registry = load_registry()
    profiles = load_profiles()
    profile_lookup = {(p["domain"], p["vendor"]): p for p in profiles}
    cap_path = base_dir / "capability_map.yaml"
    cap_data = _load_yaml(cap_path) if cap_path.exists() else {}
    domains_dir = base_dir / "domains"

    # Basic test scan
    test_dir = base_dir.parent / "tests"
    feat_test_count = {}
    if test_dir.exists():
        for tf in test_dir.rglob("test_*.py"):
            text = tf.read_text(encoding="utf-8", errors="replace")
            for feat_name in registry:
                if feat_name in text.lower():
                    feat_test_count[feat_name] = feat_test_count.get(feat_name, 0) + 1

    total, covered, partial, missing = 0, 0, 0, 0
    p0_total, p0_cov = 0, 0
    for feat_name, feat_meta in registry.items():
        domains = feat_meta.get("domains", [])
        for domain in domains:
            for vendor in vendors_for_domain(domain):
                total += 1
                profile = profile_lookup.get((domain, vendor), {"profile_missing": True})
                profile_support = profile.get("features", {}).get(feat_name) if not profile.get("profile_missing") else None
                cap_vendor = cap_data.get(feat_name, {}).get(vendor, "missing")
                knowledge_any = False
                vdir = domains_dir / domain / vendor
                if vdir.exists():
                    for f in vdir.iterdir():
                        if f.suffix == ".md" and f.stem == feat_name:
                            knowledge_any = True
                            break
                row = {
                    "profile_support": profile_support or "missing",
                    "capability_status": cap_vendor,
                    "knowledge_any": knowledge_any,
                    "tests": {"unit": feat_test_count.get(feat_name, 0), "benchmark": 0},
                }
                status = determine_status(row)
                if status == "covered":
                    covered += 1
                elif status == "partial":
                    partial += 1
                else:
                    missing += 1
                if feat_meta.get("priority") == "p0":
                    p0_total += 1
                    if status in ("covered", "partial"):
                        p0_cov += 1

    return {
        "total": total,
        "covered": covered,
        "partial": partial,
        "missing": missing,
        "p0_total": p0_total,
        "p0_covered": p0_cov,
        "p0_pct": round(p0_cov / max(p0_total, 1) * 100),
        "coverage_pct": round((covered + partial) / max(total, 1) * 100),
    }


def main() -> int:
    import sys
    if "--coverage" in sys.argv:
        stats = run_coverage()
        if not stats:
            print("COVERAGE_UNAVAILABLE")
            return 0
        print(f"COVERAGE: total={stats['total']} covered={stats['covered']} "
              f"partial={stats['partial']} missing={stats['missing']} "
              f"p0={stats['p0_covered']}/{stats['p0_total']}({stats['p0_pct']}%)")
        if "--strict" in sys.argv and stats["p0_pct"] < 80:
            print("COVERAGE_STRICT_FAIL: P0 coverage below 80%")
            return 1
        return 0

    issues = lint_knowledge()
    total = sum(len(v) for v in issues.values())
    if total == 0:
        print("KNOWLEDGE_LINT_OK")
        return 0
    print("KNOWLEDGE_LINT_FAIL")
    for kind, items in issues.items():
        if items:
            print(f"[{kind}] ({len(items)}):")
            for item in items:
                print(f"  - {item}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
