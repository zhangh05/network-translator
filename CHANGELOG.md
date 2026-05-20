# Changelog

## Unreleased — Phase 7 Production Hardening (Step 53)

### Fixed

- **P0-4**: BGP route-policy/prefix-list validator false negative — `route_policy`
  feature detection + `HIGH_RISK_CONSISTENCY_FEATURES` forces deployable=false
- **P1-3**: STP/MSTP root primary/root secondary semantic preservation —
  `_check_stp_root_role()` in ValidateNode blocks deployable when root role missing
- **P1-4**: BGP policy cross-reference deployability — `_check_bgp_policy_refs()`
  verifies route-policy/prefix-list definitions exist in output; critical warning

### Added

- **P0-1**: `analyzer_results` + `analyzer_warning_count` + `analyzer_fatal_count`
  exposed in `/api/translate` response and JSONL log
- **P0-3**: JSONL logging for `/api/projects/<id>/translate` endpoint
- **P1-1**: ObjectAnalyzer registered for `address_object` and `service_object`
  features via registry.yaml → `core.analyzers.object`
- **P1-2**: CapabilityGapNode handles list-type `analyzer_results` (from
  FeatureAnalyzerNode); analyzer warnings/fatals appear in `capability_gaps`
- **P1-5**: VERSION → `v11-phase7-step53-dev`, updated handoff/docs

### Changed

- **P0-2**: bench live report reads `analyzer_results` from `result["result"]`
  (nested), not top-level response
- `_normalize_analyzer_results()` now used in CapabilityGapNode (was dict-only)

## v11-phase6-release-ready (2026-05-19)

Phase 6: Production Hardening — the system is now deployable, observable,
verifiable, and releasable.

### Added

- **15 analyzers** covering 14 features (+ NoopAnalyzer fallback):
  NatAnalyzer, SecurityPolicyAnalyzer, AclAnalyzer, RoutePolicyAnalyzer,
  IpsecAnalyzer, QosAnalyzer, ObjectAnalyzer, VrrpAnalyzer, DhcpAnalyzer,
  VrfAnalyzer, TunnelAnalyzer, BfdAnalyzer, LacpAnalyzer, StpAnalyzer
- **Knowledge base**: 116 `.md` files across Huawei/Cisco/H3C/Ruijie/Hillstone
  /TopSec/DBAPPSecurity/DPtech, P0=179/179 (100%)
- **Analyzer consistency check** (`_consistency_check`): feature output
  verification with HIGH_RISK set (nat/acl/ipsec/route-policy/security-policy)
- **3-layer platform validator**: source-vendor residue (40+ patterns),
  style/lint (18 patterns), structure checks (VRF/ACL/prefix-list/interface)
- **Cross-reference resolution**: ASA object-group, access-list→access-group,
  route-policy↔ip-prefix for Cisco/Huawei/H3C
- **Live benchmark suite**: tier filtering (smoke/core/full), cache-hit test,
  elapsed_ms reporting, live failure detail, JSON report export
- **Benchmark coverage**: 35 cases (12 smoke/14 core/9 full)
- **Observability**: `request_id` per request, `logs/translation.jsonl` (23
  fields, no API key, config hashed), `/api/version`, deepened `/readyz`
- **Frontend production UX**: request_id display/copy, MANUAL_REVIEW
  highlighting, 3-way copy (all/deployable/report), JSON export, feature-grouped
  risk tab, state cleanup on project switch
- **Release packaging**: `.env.example`, `docs/OPERATIONS.md`,
  `docs/RELEASE_CHECKLIST.md`, `scripts/{restart,status}.sh`, updated
  `scripts/service.sh` (PORT=5008, auto-create dirs, enhanced status)
- **Deployment docs**: README deployment section, full operations guide,
  request_id troubleshooting guide

### Changed

- `scripts/service.sh`: default PORT 5000→5008, auto-creates
  `memory_data/` and `cache_data/`, status shows readyz+version
- `project_store.py`: `/api/projects/{id}/translate` returns
  `request_id`, `version`, `model` alongside `result`
- `frontend/index.html`: complete JS reorganization with `_highlightManualReview`,
  `_renderRiskTabGrouped`, copy dropdown, export, state cleanup
- `README.md`: architecture description kept as reference; deployment section
  added at top

### Fixed

- `analyzer_results` list/dict type mismatch in ValidateNode state
  (`_normalize_analyzer_results`)
- `_platform_validation` now takes `source_vendor` parameter for accurate
  residue detection
- Orphaned `_renderRiskTab` function body removed from frontend JS

### Removed

- (none)

### Infrastructure

- PLOC: ~6,400 lines (excl. benchmarks and tests)
- Tests: 345/345 pass
- Benchmarks: 35/35 static pass
- Knowledge coverage: P0=100%, P1=94.6%, missing=5/364
- Release gate score: 93.3

---

## v11-phase4-coverage-risk (2026-05-16)

Phase 4-5: Coverage expansion and analyzer implementation.

### Added

- Coverage inventory (364-row matrix)
- 71 new `.md` knowledge files (total: 116)
- 14 feature analyzers across 5 sub-phases
- 35 benchmark cases
- Frontend risk view (5 tabs)
- Release gate script
- Platform validator (initial 57 residue patterns)

### Infrastructure

- Tests: 345
- Static benchmarks: 35/35
- Analyzer coverage: P0=179/179 (100%)
- Release gate: OK (avg_score=93.3)

---

## v10-graph-ir (2026-05-13)

Phase 1-3: Graph workflow, IR translation, and rule-based validation.

### Added

- Graph execution engine (9 nodes)
- IR-based LLM translation pipeline
- Knowledge retrieval with feature-level injection
- Semantic validator (rule-based IR comparison)
- Rule-based fallback translator
- Diff engine
- 4-layer ValidateNode
- Web UI (Flask)
- 22 knowledge `.md` files (initial)
