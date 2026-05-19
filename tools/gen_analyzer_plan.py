"""Generate Step 22 analyzer planning documents."""
import json, os, yaml

DOCS_DIR = "docs/analyzers"

registry = yaml.safe_load(open("knowledge_data/features/registry.yaml"))
features = registry.get("features", {})
bench_cases = []
for p in __import__("glob").glob("bench/cases/**/*.json", recursive=True):
    if "schema" not in p:
        with open(p) as f:
            try:
                bench_cases.append(json.load(f))
            except Exception:
                pass

FEATURE_META = {
    "route_policy": {
        "priority": "p0", "risk": "medium", "domains": ["routing"],
        "reason": "与 BGP/OSPF import/export 强相关，误翻影响路由传播",
        "analyzer_class": "RoutePolicyAnalyzer",
        "bench_linked": [],
        "input_patterns": ["Huawei route-policy / ip-prefix", "H3C route-policy / ip-prefix", "Cisco route-map / prefix-list"],
        "extracted_fields": ["policy_name", "node_sequence", "permit_deny", "match_clauses", "apply_set_clauses", "referenced_prefix_list", "route_protocol_references"],
        "risk_rules": ["引用 prefix-list 缺失 → warning", "match/apply 无法映射 → warning/fatal", "顺序变化 → warning", "route-policy 被 BGP/OSPF 引用但未定义 → fatal/manual_review"],
        "validation_impact": "影响 BGP/OSPF/static 翻译质量",
        "test_cases": 6,
    },
    "ipsec": {
        "priority": "p0", "risk": "high", "domains": ["routing", "firewall"],
        "reason": "参数依赖强，缺 proposal/ike/peer/acl 导致不可用",
        "analyzer_class": "IpsecAnalyzer",
        "bench_linked": [],
        "input_patterns": ["Crypto ike/ipsec config (Cisco)", "IPsec proposal/policy (Huawei)", "IPsec policy/profile (H3C)", "IKEv1/v2 config (all)"],
        "extracted_fields": ["ike_version", "encryption_alg", "integrity_alg", "dh_group", "lifetime", "peer_ip", "local_ip", "transform_set", "acl_ref", "interface_binding"],
        "risk_rules": ["IKE proposal 缺失 → fatal", "缺少 peer IP → fatal", "transform set 不完整 → warning", "ACL 引用缺失 → warning", "接口绑定缺失 → warning"],
        "validation_impact": "IPsec 隧道配置可用性检查",
        "test_cases": 4,
    },
    "qos": {
        "priority": "p0", "risk": "medium", "domains": ["routing", "switching"],
        "reason": "厂商差异大，class/behavior/policy/service-policy 关系易丢",
        "analyzer_class": "QosAnalyzer",
        "bench_linked": [],
        "input_patterns": ["traffic classifier/behavior/policy (Huawei/H3C)", "class-map/policy-map/service-policy (Cisco)"],
        "extracted_fields": ["classifier_name", "behavior_name", "policy_name", "match_criteria", "action", "bandwidth_params", "interface_binding"],
        "risk_rules": ["classifier 引用未定义 → fatal", "behavior 被 policy 引用但不存在 → fatal", "policy 未被应用 → warning", "DSCP/cos 映射不完整 → warning"],
        "validation_impact": "QoS 策略完整性检查",
        "test_cases": 4,
    },
    "vrrp": {
        "priority": "p1", "risk": "low", "domains": ["routing", "switching"],
        "reason": "常见但结构相对简单",
        "analyzer_class": "VrrpAnalyzer",
        "bench_linked": [],
        "input_patterns": ["vrrp vrid (Huawei)", "vrrp vrid (H3C)", "standby (Cisco)"],
        "extracted_fields": ["vrid", "virtual_ip", "priority", "preempt", "track_interface", "authentication"],
        "risk_rules": ["virtual-ip 缺失 → fatal", "VRID 冲突 → warning", "priority 超出范围 → warning"],
        "validation_impact": "HA 配置完整性检查",
        "test_cases": 2,
    },
    "dhcp": {
        "priority": "p1", "risk": "low", "domains": ["routing", "switching"],
        "reason": "常见，参数映射简单",
        "analyzer_class": "DhcpAnalyzer",
        "bench_linked": [],
        "input_patterns": ["ip dhcp pool / ip dhcp excluded-address (Cisco)", "dhcp server / dhcp server ip-pool (Huawei)", "dhcp server ip-pool (H3C)"],
        "extracted_fields": ["pool_name", "network", "gateway", "dns_servers", "lease_time", "excluded_addresses"],
        "risk_rules": ["network 缺失 → fatal", "gateway 缺失 → warning"],
        "validation_impact": "DHCP 服务配置检查",
        "test_cases": 2,
    },
    "object": {
        "priority": "p1", "risk": "low", "domains": ["firewall"],
        "reason": "防火墙对象支撑 NAT/security_policy",
        "analyzer_class": "ObjectAnalyzer",
        "bench_linked": [],
        "input_patterns": ["object network / object-group network/service (Cisco ASA)", "address-set / service-set (Huawei)", "object network / object service (H3C)"],
        "extracted_fields": ["object_name", "object_type", "ip_addresses", "subnets", "tcp_ports", "udp_ports", "protocols"],
        "risk_rules": ["被 NAT/security_policy 引用但未定义 → fatal", "address-set 引用未定义 → fatal", "端口不完整 → warning"],
        "validation_impact": "防火墙对象引用完整性检查",
        "test_cases": 3,
    },
    "vrf": {
        "priority": "p2", "risk": "medium", "domains": ["routing"],
        "reason": "结构稳定，风险中等",
        "analyzer_class": "VrfAnalyzer",
        "bench_linked": [],
        "input_patterns": ["ip vrf (Cisco)", "ip vpn-instance (Huawei)", "ip vpn-instance (H3C)"],
        "extracted_fields": ["vrf_name", "rd_value", "rt_export", "rt_import", "interface_binding"],
        "risk_rules": ["RD 缺失 → warning", "被 BGP 引用但未定义 → fatal", "interface binding 缺失 → warning"],
        "validation_impact": "VRF 一致性检查",
        "test_cases": 2,
    },
    "tunnel": {
        "priority": "p2", "risk": "medium", "domains": ["routing"],
        "reason": "GRE/IPIP 结构简单，IPsec over tunnel 需单独处理",
        "analyzer_class": "TunnelAnalyzer",
        "bench_linked": [],
        "input_patterns": ["interface Tunnel (Cisco)", "interface Tunnel (Huawei)", "interface Tunnel (H3C)"],
        "extracted_fields": ["tunnel_id", "mode", "source", "destination", "key", "mtu", "tcp_mss_adjust"],
        "risk_rules": ["source 缺失 → fatal", "destination 缺失 → fatal", "mode 不明确 → warning"],
        "validation_impact": "隧道配置完整性检查",
        "test_cases": 2,
    },
    "bfd": {
        "priority": "p2", "risk": "medium", "domains": ["routing"],
        "reason": "参数简单但关联 OSPF/BGP/static",
        "analyzer_class": "BfdAnalyzer",
        "bench_linked": [],
        "input_patterns": ["bfd interval (Cisco)", "bfd session bind peer-ip (Huawei)", "bfd multi-hop (H3C)"],
        "extracted_fields": ["min_tx", "min_rx", "multiplier", "peer_ip", "local_discriminator", "remote_discriminator"],
        "risk_rules": ["被 OSPF/BGP/static 引用但未定义 → fatal", "对等体 IP 缺失 → fatal"],
        "validation_impact": "BFD 关联路由协议验证",
        "test_cases": 2,
    },
    "stp": {
        "priority": "p2", "risk": "medium", "domains": ["switching"],
        "reason": "MSTP 多实例关系需要验证",
        "analyzer_class": "StpAnalyzer",
        "bench_linked": [],
        "input_patterns": ["spanning-tree (Cisco)", "stp region-configuration (Huawei)", "stp region-configuration (H3C)"],
        "extracted_fields": ["mode", "region_name", "revision", "instance_vlan_map", "priority_per_instance"],
        "risk_rules": ["MST region 名称冲突 → warning", "instance-vlan 映射重复 → warning", "配置未生效 (active) → warning"],
        "validation_impact": "STP 区域配置一致性检查",
        "test_cases": 2,
    },
    "lacp": {
        "priority": "p2", "risk": "low", "domains": ["switching"],
        "reason": "结构简单，risk 低",
        "analyzer_class": "LacpAnalyzer",
        "bench_linked": [],
        "input_patterns": ["channel-group (Cisco)", "eth-trunk (Huawei)", "Bridge-Aggregation (H3C)"],
        "extracted_fields": ["group_id", "mode", "member_interfaces", "lacp_rate", "max_active"],
        "risk_rules": ["成员接口不足 → warning", "member interface 引用未定义 → warning"],
        "validation_impact": "LACP/链路聚合配置检查",
        "test_cases": 2,
    },
}

# Build bench_linked mapping
for bc in bench_cases:
    bc_name = bc.get("name", "")
    bc_feats = bc.get("features", [])
    for feat, meta in FEATURE_META.items():
        for bf in bc_feats:
            if bf == feat or (feat == "object" and bf in ("address_object", "service_object")):
                if bc_name not in meta["bench_linked"]:
                    meta["bench_linked"].append(bc_name)

# Sort bench_linked
for feat, meta in FEATURE_META.items():
    meta["bench_linked"] = sorted(meta["bench_linked"])

# ── 1. analyzer_plan.json ──
plan = []
for feat, meta in sorted(FEATURE_META.items()):
    plan.append({
        "feature": feat,
        "priority": meta["priority"],
        "risk": meta["risk"],
        "domains": meta["domains"],
        "analyzer_class": meta["analyzer_class"],
        "reason": meta["reason"],
        "bench_linked": meta["bench_linked"],
        "test_cases_planned": meta["test_cases"],
    })

with open(f"{DOCS_DIR}/analyzer_plan.json", "w") as f:
    json.dump(plan, f, ensure_ascii=False, indent=2)
print(f"Wrote {DOCS_DIR}/analyzer_plan.json ({len(plan)} analyzers)")

# ── 2. feature_risk_matrix.md ──
lines = [
    "# Feature Risk Matrix — Analyzer Coverage",
    "",
    "## Legend",
    "",
    "| Column | Meaning |",
    "|--------|---------|",
    "| Feature | Feature name from registry |",
    "| Risk | Overall risk level (high/medium/low) |",
    "| Domains | Applicable domains |",
    "| Has Analyzer | Whether an analyzer exists today |",
    "| Priority | Planned analyzer priority |",
    "| Planned | Analyzer planned for this feature |",
    "| Bench Cases | Linked benchmark case count |",
    "| Test Cases | Planned unit tests for this analyzer |",
    "",
    "## Matrix",
    "",
    "| # | Feature | Risk | Domains | Has Analyzer | Priority | Planned | Bench | Tests |",
    "|---|---------|------|---------|-------------|----------|---------|-------|-------|",
]

idx = 0
for feat, meta in sorted(FEATURE_META.items()):
    idx += 1
    r = features.get(feat, {})
    risk = r.get("risk", meta["risk"]).upper()
    domains = ",".join(r.get("domains", meta["domains"]))
    has_analyzer = r.get("analyzer", False)
    has_str = f"✅ {r['analyzer']}" if has_analyzer else "❌"
    lines.append(
        f"| {idx} | {feat} | {risk} | {domains} | {has_str} | "
        f"{meta['priority']} | {meta['analyzer_class']} | "
        f"{len(meta['bench_linked'])} | {meta['test_cases']} |"
    )

lines += ["", "## Existing Analyzers", "",
           "| Analyzer | Feature | Status | Lines of Code |",
           "|----------|---------|--------|--------------:|",
           "| NatAnalyzer | nat | ✅ Production | 381 |",
           "| SecurityPolicyAnalyzer | security_policy | ✅ Production | 528 |",
           "| AclAnalyzer | acl | ✅ Production | ~300 |",
           "| NoopAnalyzer | (fallback) | ✅ Production | ~30 |",
           ""]

with open(f"{DOCS_DIR}/feature_risk_matrix.md", "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"Wrote {DOCS_DIR}/feature_risk_matrix.md")

# ── 3. analyzer_contract.md ──
contract_lines = [
    "# Analyzer Contract",
    "",
    "## Overview",
    "",
    "Each analyzer implements `FeatureAnalyzer` (ABC in `core/analyzers/base.py`) and produces a `FeatureAnalysis` dataclass.",
    "",
    "## Interface",
    "",
    "```python",
    "class FeatureAnalyzer(ABC):",
    "    @abstractmethod",
    "    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:",
    "        pass",
    "",
    "    @property",
    "    @abstractmethod",
    "    def feature_name(self) -> str:",
    "        pass",
    "```",
    "",
    "## FeatureAnalysis Output",
    "",
    "```python",
    "@dataclass",
    "class FeatureAnalysis:",
    "    feature: str                    # Feature name, e.g. \"nat\"",
    "    status: str = \"skipped\"        # \"analyzed\" | \"skipped\" | \"error\"",
    "    risk_level: str = \"info\"       # \"info\" | \"warning\" | \"fatal\"",
    "    manual_review_required: bool = False",
    "    rules: list = []                # Structured rule entries",
    "    references: dict = {}           # Referenced objects (ACLs, pools, prefix-lists...)",
    "    missing_context: list = []      # Missing context items (strings)",
    "    source_lines: list = []         # Matched source config lines",
    "    notes: list = []                # Human-readable notes",
    "    metadata: dict = {}             # Extra metadata",
    "```",
    "",
    "## Consumer: CapabilityGapNode",
    "",
    "`CapabilityGapNode` (in `core/graph/nodes.py`) runs `registry.analyze_all()` in `_get_analyzer_results()`,",
    "merges results into structured `capability_gaps` and passes `analyzer_context` to `TranslateNode`.",
    "",
    "## Consumer: ValidateNode",
    "",
    "`ValidateNode` uses analyzer results in its Layer 3 (Domain) and Layer 4 (Feature) validation:",
    "- `risk_level='fatal'` → `deployable=False`",
    "- `risk_level='warning'` → validation errors added",
    "- `missing_context` items → specific validation errors",
    "",
    "## Consumer: TranslateNode Prompt",
    "",
    "Analyzer context is injected as a structured `analyzer_context` JSON param in the LLM prompt.",
    "Fields used: `missing_context`, `manual_review_required`, `risk_level`, `rules`.",
    "",
    "## Analyzer-Specific Contracts",
    "",
]

for feat, meta in sorted(FEATURE_META.items()):
    contract_lines += [
        f"### {meta['analyzer_class']} ({feat})",
        f"",
        f"- **Priority**: {meta['priority']}",
        f"- **Risk**: {meta['risk']}",
        f"- **Domains**: {', '.join(meta['domains'])}",
        f"- **Reason**: {meta['reason']}",
        f"",
        f"**Input Patterns**:",
    ]
    for pat in meta["input_patterns"]:
        contract_lines.append(f"  - `{pat}`")
    contract_lines += [
        f"",
        f"**Extracted Fields**:",
    ]
    for f in meta["extracted_fields"]:
        contract_lines.append(f"  - `{f}`")
    contract_lines += [
        f"",
        f"**Risk Rules**:",
    ]
    for rule in meta["risk_rules"]:
        contract_lines.append(f"  - {rule}")
    contract_lines += [
        f"",
        f"**Validation Impact**: {meta['validation_impact']}",
        f"**Test Cases Planned**: {meta['test_cases']}",
        f"",
    ]
    if meta['bench_linked']:
        contract_lines.append("**Linked Bench Cases**:")
        for bc in meta['bench_linked']:
            contract_lines.append(f"  - `{bc}`")
        contract_lines.append("")

with open(f"{DOCS_DIR}/analyzer_contract.md", "w") as f:
    f.write("\n".join(contract_lines) + "\n")
print(f"Wrote {DOCS_DIR}/analyzer_contract.md")

# ── 4. roadmap.md ──
roadmap_lines = [
    "# Analyzer Roadmap",
    "",
    "## Milestones",
    "",
    "| Phase | Scope | Analyzers | Target Date | Bench Cases | Dependencies |",
    "|-------|-------|-----------|-------------|-------------|-------------|",
    "",
]

milestones = [
    ("Phase 5-A", "P0 Analyzer Core", ["RoutePolicyAnalyzer", "IpsecAnalyzer", "QosAnalyzer"], 14, [
        "None (builds on existing framework)",
    ]),
    ("Phase 5-B", "P1 Analyzer Expansion", ["VrrpAnalyzer", "DhcpAnalyzer", "ObjectAnalyzer"], 10, [
        "Phase 5-A complete (framework validated)",
        "ObjectAnalyzer may depend on AddressObject/ServiceObject knowledge",
    ]),
    ("Phase 5-C", "P2 Analyzer Completion", ["VrfAnalyzer", "TunnelAnalyzer", "BfdAnalyzer", "StpAnalyzer", "LacpAnalyzer"], 15, [
        "Phase 5-B complete",
    ]),
]

FEATURE_META_BY_CLASS = {m["analyzer_class"]: (feat, m) for feat, m in FEATURE_META.items()}

for phase, scope, analyzer_list, bench_cnt, deps in milestones:
    bc_names = set()
    total_tests = 0
    a_names = ", ".join(analyzer_list)
    for an in analyzer_list:
        if an in FEATURE_META_BY_CLASS:
            feat, meta = FEATURE_META_BY_CLASS[an]
            bc_names.update(meta["bench_linked"])
            total_tests += meta["test_cases"]
    roadmap_lines.append(f"| {phase} | {scope} | {a_names} | {len(bc_names)} bench, {total_tests} tests | {'; '.join(str(d) for d in deps)} |")

roadmap_lines += [
    "",
    "## Feature → Bench Case Mapping",
    "",
    "| Analyzer | Feature | Linked Bench Cases |",
    "|----------|---------|-------------------|",
]

for feat, meta in sorted(FEATURE_META.items()):
    bc_list = ", ".join(f"`{bc}`" for bc in meta["bench_linked"]) if meta["bench_linked"] else "(none)"
    roadmap_lines.append(f"| {meta['analyzer_class']} | {feat} | {bc_list} |")

roadmap_lines += [
    "",
    "## Total Effort Estimate",
    "",
    "| Phase | Analyzers | Planned Cases | Bench Linked | Dependency |",
    "|-------|-----------|--------------:|-------------:|-----------|",
    "| Phase 5-A | RoutePolicyAnalyzer, IpsecAnalyzer, QosAnalyzer | 14 | dedicated cases | framework ready |",
    "| Phase 5-B | VrrpAnalyzer, DhcpAnalyzer, ObjectAnalyzer | 7 | shared cases | Phase 5-A done |",
    "| Phase 5-C | VrfAnalyzer, TunnelAnalyzer, BfdAnalyzer, StpAnalyzer, LacpAnalyzer | 10 | shared cases | Phase 5-B done |",
    "| **Total** | **11 analyzers** | **31** | **35 bench cases** | |",
]

with open(f"{DOCS_DIR}/roadmap.md", "w") as f:
    f.write("\n".join(roadmap_lines) + "\n")
print(f"Wrote {DOCS_DIR}/roadmap.md")

print("\nDone — all 4 documents generated.")
