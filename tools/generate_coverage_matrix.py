#!/usr/bin/env python3
"""Generate a comprehensive corpus coverage matrix from annotations + knowledge data.

Produces:
  - reports/coverage_matrix.md   (human-readable report)
  - reports/coverage_matrix.json (machine-readable data)
"""

import json
import yaml
from pathlib import Path
from collections import Counter, defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent

ANNOTATIONS_DIR = PROJECT_ROOT / "corpus" / "annotations"
CAPABILITY_MAP = PROJECT_ROOT / "knowledge_data" / "capability_map.yaml"
FEATURE_REGISTRY = PROJECT_ROOT / "knowledge_data" / "features" / "registry.yaml"
OUTPUT_DIR = PROJECT_ROOT / "reports"

ALL_VENDORS = ["cisco", "huawei", "h3c", "ruijie", "hillstone", "topsec", "dbappsecurity", "dptech"]
ALL_DOMAINS = ["routing", "switching", "firewall"]
PRIORITY_ORDER = {"p0": 0, "p1": 1, "p2": 2}


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def load_annotations():
    entries = []
    for fpath in sorted(ANNOTATIONS_DIR.glob("*.annotation.json")):
        with open(fpath) as f:
            data = json.load(f)
        cls = data.get("classification", {})
        ann = data.get("annotation", {})
        exp = ann.get("expected_translation", {})
        ver = ann.get("verification", {})
        bench = data.get("benchmark", {})
        entries.append({
            "id": data.get("id", fpath.stem),
            "path": str(fpath.relative_to(PROJECT_ROOT)),
            "source_domain": cls.get("domain", ""),
            "source_vendor": cls.get("vendor", ""),
            "source_platform": cls.get("platform", ""),
            "features": cls.get("features", []),
            "risk": cls.get("risk", ""),
            "target_vendor": exp.get("target_vendor", ""),
            "deployable": ver.get("deployable"),
            "manual_review_required": ver.get("manual_review_required"),
            "tier": bench.get("tier", "unknown"),
            "status": data.get("status", "unknown"),
            "live_pass": bench.get("live_pass"),
            "static_pass": bench.get("static_pass"),
        })
    return entries


def build_vendor_domain_matrix(entries):
    rows = []
    for domain in ALL_DOMAINS:
        filtered = [e for e in entries if e["source_domain"] == domain]
        for vendor in ALL_VENDORS:
            matched = [e for e in filtered if e["source_vendor"] == vendor]
            if matched:
                targets = set(e["target_vendor"] for e in matched)
                features = set()
                for e in matched:
                    features.update(e["features"])
                rows.append({
                    "domain": domain,
                    "source_vendor": vendor,
                    "count": len(matched),
                    "target_vendors": sorted(targets),
                    "features": sorted(features),
                    "ids": [e["id"] for e in matched],
                })
    return rows


def build_feature_vendor_matrix(entries, capability_map, registry):
    all_features = list(registry.get("features", {}).keys())
    rows = []

    for feat in all_features:
        cap = capability_map.get(feat, {})
        feat_reg = registry.get("features", {}).get(feat, {})
        feat_domains = feat_reg.get("domains", [])
        feat_priority = feat_reg.get("priority", "p2")
        feat_risk = feat_reg.get("risk", "low")

        vendor_stats = {}
        for vendor in ALL_VENDORS:
            corpus_ids = sorted(
                e["id"] for e in entries
                if feat in e["features"] and e["source_vendor"] == vendor
            )
            target_ids = sorted(
                e["id"] for e in entries
                if feat in e["features"] and e["target_vendor"] == vendor
            )
            vendor_stats[vendor] = {
                "capability": cap.get(vendor, "unknown"),
                "corpus_count": len(corpus_ids),
                "target_count": len(target_ids),
                "corpus_ids": corpus_ids,
                "target_ids": target_ids,
            }

        rows.append({
            "feature": feat,
            "domains": feat_domains,
            "priority": feat_priority,
            "risk": feat_risk,
            "corpus_total": sum(v["corpus_count"] for v in vendor_stats.values()),
            "target_total": sum(v["target_count"] for v in vendor_stats.values()),
            "vendors": vendor_stats,
        })

    return rows


def build_coverage_gaps(entries, capability_map, registry):
    all_features = list(registry.get("features", {}).keys())
    gaps = []
    for feat in all_features:
        cap = capability_map.get(feat, {})
        feat_reg = registry.get("features", {}).get(feat, {})
        for vendor in ALL_VENDORS:
            if cap.get(vendor) not in ("supported", "partial"):
                continue
            corpus_count = sum(
                1 for e in entries
                if feat in e["features"] and e["source_vendor"] == vendor
            )
            if corpus_count == 0:
                gaps.append({
                    "feature": feat,
                    "vendor": vendor,
                    "type": "missing_corpus",
                    "domains": feat_reg.get("domains", []),
                    "priority": feat_reg.get("priority", "p2"),
                })
    return gaps


def format_cell(value, threshold=0):
    if isinstance(value, bool):
        return "✓" if value else "✗"
    if isinstance(value, int):
        return str(value) if value > threshold else "—"
    return str(value) if value else "—"


def generate_report(entries, vendor_domain, feature_vendor, gaps, capability_map, registry):
    lines = []
    def w(s=""):
        lines.append(s)

    w("# Coverage Matrix")
    w()
    w(f"Generated for: {PROJECT_ROOT.joinpath('VERSION').read_text().strip()}")
    w(f"Corpus entries: {len(entries)}")
    w(f"Registered features: {len(registry.get('features', {}))}")
    w()
    from itertools import chain
    all_corpus_features = list(chain.from_iterable(e["features"] for e in entries))
    corpus_feature_counts = Counter(all_corpus_features)
    w(f"Unique features in corpus: {len(corpus_feature_counts)}")
    w()

    # ── Domain × Vendor ──
    w("## Domain × Source Vendor Coverage")
    w()
    w("| Domain | Vendor | Cases | Target Vendors | Features |")
    w("|--------|--------|-------|----------------|----------|")
    for r in vendor_domain:
        targets = ", ".join(r["target_vendors"]) if r["target_vendors"] else "—"
        feats = ", ".join(r["features"]) if r["features"] else "—"
        w(f"| {r['domain']} | {r['source_vendor']} | {r['count']} | {targets} | {feats} |")
    w()

    # ── Domain summary ──
    w("### Domain Summary")
    w()
    domain_counts = Counter(e["source_domain"] for e in entries)
    for domain in ALL_DOMAINS:
        w(f"- **{domain}**: {domain_counts.get(domain, 0)} cases")
    w()

    # ── Feature Priority Summary ──
    w("## Feature Priority Coverage")
    w()
    w("| Priority | Registered | In Corpus | Coverage % | Missing |")
    w("|----------|------------|-----------|------------|---------|")
    feat_reg = registry.get("features", {})
    corpus_features = set()
    for e in entries:
        corpus_features.update(e["features"])

    for pri in ("p0", "p1", "p2"):
        reg_count = sum(1 for f in feat_reg.values() if f.get("priority") == pri)
        in_corpus = set(
            f for f, v in feat_reg.items()
            if v.get("priority") == pri and f in corpus_features
        )
        corpus_count = len(in_corpus)
        pct = f"{corpus_count / reg_count * 100:.0f}%" if reg_count else "—"
        missing = sorted(set(
            f for f, v in feat_reg.items()
            if v.get("priority") == pri and f not in corpus_features
        ))
        missing_str = ", ".join(missing) if missing else "—"
        w(f"| {pri.upper()} | {reg_count} | {corpus_count} | {pct} | {missing_str} |")
    w()

    # ── Feature × Vendor ──
    w("## Feature × Vendor Coverage (Source)")
    w()
    header = "| Feature | Pri | Risk | " + " | ".join(v.capitalize() for v in ALL_VENDORS) + " | Total |"
    w(header)
    sep = "|---------|-----|------|" + "|".join("--------" for _ in ALL_VENDORS) + "|-------|"
    w(sep)
    for r in sorted(feature_vendor, key=lambda x: (PRIORITY_ORDER.get(x["priority"], 99), x["feature"])):
        cells = [r["feature"], r["priority"].upper(), r["risk"].capitalize()]
        for vendor in ALL_VENDORS:
            v = r["vendors"][vendor]
            val = v["corpus_count"]
            if v["capability"] == "supported":
                cells.append(f"**{val}**" if val else f"~{val}~")
            elif v["capability"] == "partial":
                cells.append(f"*{val}*" if val else f"~{val}~")
            elif v["capability"] == "unknown":
                cells.append(str(val) if val else "—")
            else:
                cells.append(str(val) if val else "—")
        cells.append(str(r["corpus_total"]))
        w("| " + " | ".join(cells) + " |")
    w()

    # ── Target coverage ──
    w("## Feature × Vendor Coverage (Target)")
    w()
    w("| Feature | Pri | " + " | ".join(v.capitalize() for v in ALL_VENDORS) + " | Total |")
    w("|---------|-----|" + "|".join("--------" for _ in ALL_VENDORS) + "|-------|")
    for r in sorted(feature_vendor, key=lambda x: (PRIORITY_ORDER.get(x["priority"], 99), x["feature"])):
        cells = [r["feature"], r["priority"].upper()]
        for vendor in ALL_VENDORS:
            v = r["vendors"][vendor]
            cells.append(str(v["target_count"]) if v["target_count"] else "—")
        cells.append(str(r["target_total"]))
        w("| " + " | ".join(cells) + " |")
    w()

    # ── Gaps ──
    w("## Coverage Gaps (Known Support Missing Corpus)")
    w()
    if gaps:
        w("| Feature | Vendor | Priority | Domains |")
        w("|---------|--------|----------|---------|")
        for g in sorted(gaps, key=lambda x: (PRIORITY_ORDER.get(x["priority"], 99), x["feature"], x["vendor"])):
            domains = ", ".join(g["domains"]) if g["domains"] else "—"
            w(f"| {g['feature']} | {g['vendor']} | {g['priority'].upper()} | {domains} |")
    else:
        w("No gaps found — all known-supported features have corpus coverage.")
    w()

    # ── Knowledge vs Corpus ──
    w("## Knowledge vs Corpus Coverage")
    w()
    w("This table shows how many features are supported per vendor in the knowledge base")
    w("vs how many have corpus test cases.")
    w()
    w("| Vendor | Knowledge Supported | Corpus Source Coverage | Corpus Target Coverage |")
    w("|--------|--------------------|----------------------|----------------------|")
    for vendor in ALL_VENDORS:
        kb_supported = sum(
            1 for feat, cap in capability_map.items()
            if cap.get(vendor) in ("supported", "partial")
        )
        corpus_source = len(set(
            e["id"] for e in entries if e["source_vendor"] == vendor
        ))
        corpus_target = len(set(
            e["id"] for e in entries if e["target_vendor"] == vendor
        ))
        w(f"| {vendor.capitalize()} | {kb_supported} | {corpus_source} | {corpus_target} |")
    w()

    # ── Risk distribution ──
    w("## Risk Distribution")
    w()
    risk_counts = Counter(e.get("risk", "") for e in entries)
    for risk in ("high", "medium", "low"):
        w(f"- **{risk.capitalize()}**: {risk_counts.get(risk, 0)} cases")
    w()

    # ── Deployability profile ──
    w("## Deployability Profile")
    w()
    dep_true = sum(1 for e in entries if e.get("deployable") is True)
    dep_false = sum(1 for e in entries if e.get("deployable") is False)
    mrev_true = sum(1 for e in entries if e.get("manual_review_required") is True)
    mrev_false = sum(1 for e in entries if e.get("manual_review_required") is False)
    w(f"- **Deployable**: {dep_true} cases")
    w(f"- **Not deployable**: {dep_false} cases")
    w(f"- **Manual review required**: {mrev_true} cases")
    w(f"- **No manual review**: {mrev_false} cases")
    w()

    return "\n".join(lines)


def build_json_output(entries, vendor_domain, feature_vendor, gaps, capability_map, registry):
    return {
        "version": PROJECT_ROOT.joinpath('VERSION').read_text().strip(),
        "corpus": {
            "total_entries": len(entries),
            "by_domain": dict(Counter(e["source_domain"] for e in entries)),
            "by_source_vendor": dict(Counter(e["source_vendor"] for e in entries)),
            "by_target_vendor": dict(Counter(e["target_vendor"] for e in entries)),
            "by_risk": dict(Counter(e.get("risk", "") for e in entries)),
            "by_tier": dict(Counter(e.get("tier", "") for e in entries)),
            "deployable_count": sum(1 for e in entries if e.get("deployable") is True),
            "manual_review_count": sum(1 for e in entries if e.get("manual_review_required") is True),
        },
        "feature_registry": {
            "total": len(registry.get("features", {})),
            "by_priority": dict(Counter(
                v.get("priority", "p2") for v in registry.get("features", {}).values()
            )),
            "by_risk": dict(Counter(
                v.get("risk", "low") for v in registry.get("features", {}).values()
            )),
        },
        "vendor_domain": vendor_domain,
        "feature_vendor": [
            {
                "feature": r["feature"],
                "priority": r["priority"],
                "risk": r["risk"],
                "domains": r["domains"],
                "corpus_total": r["corpus_total"],
                "target_total": r["target_total"],
                "vendors": [
                    {
                        "vendor": v,
                        "capability": vs["capability"],
                        "corpus_count": vs["corpus_count"],
                        "target_count": vs["target_count"],
                    }
                    for v, vs in r["vendors"].items()
                ],
            }
            for r in feature_vendor
        ],
        "gaps": [
            {
                "feature": g["feature"],
                "vendor": g["vendor"],
                "priority": g["priority"],
                "domains": g["domains"],
            }
            for g in gaps
        ],
        "knowledge_summary": {
            vendor: sum(
                1 for feat, cap in capability_map.items()
                if cap.get(vendor) in ("supported", "partial")
            )
            for vendor in ALL_VENDORS
        },
    }


def main():
    entries = load_annotations()
    capability_map = load_yaml(CAPABILITY_MAP)
    registry = load_yaml(FEATURE_REGISTRY)

    vendor_domain = build_vendor_domain_matrix(entries)
    feature_vendor = build_feature_vendor_matrix(entries, capability_map, registry)
    gaps = build_coverage_gaps(entries, capability_map, registry)

    report = generate_report(entries, vendor_domain, feature_vendor, gaps, capability_map, registry)
    json_data = build_json_output(entries, vendor_domain, feature_vendor, gaps, capability_map, registry)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    md_path = OUTPUT_DIR / "coverage_matrix.md"
    md_path.write_text(report)
    print(f"Report: {md_path}")

    json_path = OUTPUT_DIR / "coverage_matrix.json"
    with open(json_path, "w") as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    print(f"Data: {json_path}")


if __name__ == "__main__":
    main()
