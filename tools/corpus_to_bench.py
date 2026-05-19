#!/usr/bin/env python3
"""corpus_to_bench.py — Convert corpus annotations + sanitized configs to benchmark cases.

Usage:
    python tools/corpus_to_bench.py              # convert all eligible entries
    python tools/corpus_to_bench.py --dry-run     # preview only
    python tools/corpus_to_bench.py --entry fw-nat-001  # single entry
"""

import json, os, sys, argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS_DIR = os.path.join(PROJECT_ROOT, "corpus")
SANITIZED_DIR = os.path.join(CORPUS_DIR, "sanitized")
ANNOTATIONS_DIR = os.path.join(CORPUS_DIR, "annotations")
BENCH_CORPUS_DIR = os.path.join(PROJECT_ROOT, "bench", "cases", "corpus")
SCHEMA_PATH = os.path.join(PROJECT_ROOT, "bench", "cases", "schema.json")

FEATURE_DOMAIN_MAP = {
    "firewall": {
        "nat", "nat_source", "nat_server", "security_policy",
        "zone", "acl", "ipsec", "dns", "object", "address_object",
    },
    "routing": {
        "ospf", "bgp", "static_route", "route_policy",
        "vrf", "bfd", "tunnel", "mpls", "pbr",
    },
    "switching": {
        "vlan", "stp", "lacp", "port_channel", "lldp", "mac",
    },
}

OVERLAP_FEATURES = {"interface"}  # voted below


def detect_domain(features):
    scores = {"firewall": 0, "routing": 0, "switching": 0}
    for f in features:
        fl = f.lower()
        if fl in OVERLAP_FEATURES:
            for d in scores:
                scores[d] += 0.5
            continue
        for domain, dfeatures in FEATURE_DOMAIN_MAP.items():
            if fl in dfeatures:
                scores[domain] += 1
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        for f in features:
            fl = f.lower()
            if "nat" in fl or "firewall" in fl or "security" in fl:
                return "firewall"
            if "ospf" in fl or "bgp" in fl or "route" in fl:
                return "routing"
            if "vlan" in fl or "stp" in fl:
                return "switching"
        return "routing"
    return best


VENDOR_PLATFORM_MAP = {
    "cisco": {"firewall": "asa", "routing": "ios", "switching": "ios"},
    "huawei": {"firewall": "vrp", "routing": "vrp", "switching": "vrp"},
    "h3c": {"firewall": "comware", "routing": "comware", "switching": "comware"},
    "ruijie": {"firewall": "ruijie", "routing": "ruijie", "switching": "ruijie"},
    "hillstone": {"firewall": "hillstone", "routing": "hillstone", "switching": "hillstone"},
    "topsec": {"firewall": "topsec", "routing": "topsec", "switching": "topsec"},
    "dbappsecurity": {"firewall": "dbappsecurity", "routing": "dbappsecurity", "switching": "dbappsecurity"},
    "dptech": {"firewall": "dptech", "routing": "dptech", "switching": "dptech"},
}


def get_platform(vendor, domain):
    return VENDOR_PLATFORM_MAP.get(vendor, {}).get(domain, vendor)


def load_schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def validate_case(case):
    errors = []
    schema = load_schema()
    for key in schema.get("required", []):
        if key not in case:
            errors.append(f"missing required key: {key}")
    exp = case.get("expected", {})
    for r in ["deployable", "manual_review_required", "no_markdown_fence", "no_placeholder"]:
        if r not in exp:
            errors.append(f"expected missing: {r}")
    features = case.get("features", [])
    if not isinstance(features, list) or len(features) == 0:
        errors.append("features must be non-empty list")
    cfg = case.get("source_config", "")
    if not isinstance(cfg, str) or len(cfg.strip()) < 10:
        errors.append("source_config too short")
    for key in ("source_domain", "target_domain"):
        if case.get(key) not in ("routing", "switching", "firewall"):
            errors.append(f"{key} must be routing/switching/firewall, got {case.get(key)}")
    return errors


def convert_entry(annotation_path, dry_run=False):
    with open(annotation_path) as f:
        annotation = json.load(f)

    entry_id = annotation["id"]
    cls = annotation["classification"]
    anno = annotation["annotation"]
    verify = anno["verification"]
    bm = annotation["benchmark"]
    exp_trans = anno["expected_translation"]

    sanitized_rel = annotation["config"]["sanitized_path"]
    sanitized_path = os.path.join(SANITIZED_DIR, os.path.basename(sanitized_rel))
    if not os.path.exists(sanitized_path):
        print(f"  SKIP {entry_id}: sanitized file not found: {sanitized_path}")
        return None

    with open(sanitized_path) as f:
        sanitized_text = f.read().strip()

    features = cls["features"]
    source_domain = cls.get("domain") or detect_domain(features)
    target_vendor = exp_trans["target_vendor"]
    target_domain = source_domain

    expected = {
        "deployable": bool(verify.get("deployable", True)),
        "manual_review_required": bool(verify.get("manual_review_required", False)),
        "no_markdown_fence": True,
        "no_placeholder": True,
    }

    key_lines = exp_trans.get("key_lines", [])
    if key_lines:
        expected["must_include"] = key_lines

    must_not = exp_trans.get("must_not_contain", [])
    if must_not:
        expected["must_not_include"] = must_not

    if not expected["deployable"] or expected["manual_review_required"]:
        expected["max_level"] = "error"
    else:
        expected["max_level"] = "warning"

    source_platform = cls.get("platform", get_platform(cls["vendor"], source_domain))
    target_platform = get_platform(target_vendor, target_domain)

    case_name = f"corpus-{entry_id}"
    risk = cls.get("risk", "medium")
    tier = bm.get("tier")
    if tier not in ("smoke", "core", "full"):
        risk_levels = {"low": "smoke", "medium": "core", "high": "full"}
        tier = risk_levels.get(risk, "full")

    case = {
        "name": case_name,
        "source_domain": source_domain,
        "source_vendor": cls["vendor"],
        "source_platform": source_platform,
        "target_domain": target_domain,
        "target_vendor": target_vendor,
        "target_platform": target_platform,
        "features": features,
        "risk": risk,
        "tier": tier,
        "source_config": sanitized_text,
        "expected": expected,
        "corpus_ref": {
            "sanitized_file": sanitized_rel,
            "annotation_file": os.path.relpath(annotation_path, ANNOTATIONS_DIR),
        },
    }

    domain_dir = os.path.join(BENCH_CORPUS_DIR, source_domain)
    case_path = os.path.join(domain_dir, f"{case_name}.json")

    if not dry_run:
        os.makedirs(domain_dir, exist_ok=True)
        with open(case_path, "w") as f:
            json.dump(case, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"  WRITE {case_name} -> {case_path}")

        annotation["benchmark"]["case_generated"] = True
        annotation["benchmark"]["case_path"] = os.path.relpath(case_path, CORPUS_DIR)
        annotation["status"] = "bench_generated"
        with open(annotation_path, "w") as f:
            json.dump(annotation, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"  UPDATE annotation {os.path.basename(annotation_path)} -> status=bench_generated")
    else:
        print(f"  [DRY-RUN] would write  {case_name} -> {case_path}")
        print(f"  [DRY-RUN] would update {os.path.basename(annotation_path)}")

    return case


def main():
    parser = argparse.ArgumentParser(description="Convert corpus entries to benchmark cases")
    parser.add_argument("--dry-run", action="store_true", help="Preview only, no writes")
    parser.add_argument("--entry", help="Convert only specific entry ID, e.g. fw-nat-001")
    args = parser.parse_args()

    annotation_files = sorted(os.listdir(ANNOTATIONS_DIR))
    annotation_files = [f for f in annotation_files if f.endswith(".annotation.json")]
    if not annotation_files:
        print("No annotation files found.")
        return 1

    converted = 0
    skipped = 0
    errors = 0

    for af in annotation_files:
        entry_id = af.replace(".txt.annotation.json", "")
        if args.entry and entry_id != args.entry:
            continue
        annotation_path = os.path.join(ANNOTATIONS_DIR, af)
        print(f"Processing {entry_id}...")
        result = convert_entry(annotation_path, dry_run=args.dry_run)
        if result is None:
            skipped += 1
            continue
        validation_errors = validate_case(result)
        if validation_errors:
            print(f"  ERROR: {entry_id} case failed validation:")
            for ve in validation_errors:
                print(f"    - {ve}")
            errors += 1
        else:
            print(f"  OK: {entry_id} case passes schema validation")
            converted += 1

    print(f"\nSummary: {converted} generated, {skipped} skipped, {errors} errors")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
