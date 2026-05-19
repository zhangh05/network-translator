# File Index

Last updated: 2026-05-19

## Top-Level Entry Points

| File | Role |
|------|------|
| `web_app.py` | Flask web service (production: gunicorn) |
| `project_store.py` | Project CRUD, `/api/projects/*` routes, `request_id` generation |
| `run.py` | Interactive CLI entry |
| `llm_settings.py` | LLM model/API settings loader, shared client factory |

## `core/` — Translation Pipeline

| File | Role |
|------|------|
| `__init__.py` | LLM singleton (Anthropic + OpenAI compatible), threading-safe |
| `ir.py` | LLM-driven IR translation prompts and helpers |
| `semantic_compare.py` | Rule-based IR equivalence check |
| `rule_translator.py` | Rule-based fallback translator (no LLM) |
| `context.py` | GSSC context pipeline |
| `graph/base.py` | Node/Edge/State base classes |
| `graph/nodes.py` | ValidateNode, TranslateNode, CapabilityGapNode, etc. |
| `graph/translation_graph.py` | 9-node workflow graph definition |
| `analyzers/__init__.py` | Broker, all 15 analyzer imports |
| `analyzers/base.py` | FeatureAnalyzer ABC, FeatureAnalysis dataclass (9 fields) |
| `analyzers/registry.py` | AnalyzerRegistry — loads from registry.yaml `analyzer` key |
| `analyzers/{feature}_analyzer.py` | 14 feature analyzers + NoopAnalyzer fallback |

### Analyzers (15 total)

| Analyzer | File | Tests |
|----------|------|-------|
| NatAnalyzer | `analyzers/nat_analyzer.py` | 11 |
| SecurityPolicyAnalyzer | `analyzers/security_policy_analyzer.py` | 11 |
| AclAnalyzer | `analyzers/acl_analyzer.py` | 10 |
| RoutePolicyAnalyzer | `analyzers/route_policy_analyzer.py` | 11 |
| IpsecAnalyzer | `analyzers/ipsec_analyzer.py` | 11 |
| QosAnalyzer | `analyzers/qos_analyzer.py` | 11 |
| ObjectAnalyzer | `analyzers/object_analyzer.py` | 10 |
| VrrpAnalyzer | `analyzers/vrrp_analyzer.py` | 10 |
| DhcpAnalyzer | `analyzers/dhcp_analyzer.py` | 10 |
| VrfAnalyzer | `analyzers/vrf_analyzer.py` | 10 |
| TunnelAnalyzer | `analyzers/tunnel_analyzer.py` | 12 |
| BfdAnalyzer | `analyzers/bfd_analyzer.py` | 11 |
| LacpAnalyzer | `analyzers/lacp_analyzer.py` | 11 |
| StpAnalyzer | `analyzers/stp_analyzer.py` | 12 |
| NoopAnalyzer | `analyzers/noop_analyzer.py` | fallback |

## `knowledge_data/` — Knowledge Base

| Path | Content |
|------|---------|
| `registry.yaml` | 44+ features with priority/risk/domains/analyzer binding |
| `capability_map.yaml` | P0+P1 feature→vendor capability, 8 vendors |
| `features/` | Feature-level knowledge `.md` files |
| `domins/{domain}/{vendor}/{feature}.md` | Domain-organized knowledge (Phase 2+, takes priority) |
| `cisco/`, `huawei/`, `h3c/` | Legacy vendor-organized knowledge (Phase 1, fallback) |

## `tools/` — Utility Tools

| File | Role |
|------|------|
| `__init__.py` | ConfigParser, ConfigDiffer, ConfigValidator, KnowledgeRetriever |
| `knowledge_manager.py` | IR-driven knowledge retrieval (file-based cache, per-IR-type) |
| `knowledge_lint.py` | Knowledge file linting + `--coverage` coverage check |
| `coverage_inventory.py` | 364-row coverage matrix scanner |
| `gen_bench_cases.py` | Benchmark case generator |

## `tests/` — Test Suite (345 tests)

| File | Role |
|------|------|
| `conftest.py` | Shared fixtures |
| `test_all.py` | Integration and regression tests |
| `test_e2e.py` | End-to-end pipeline tests |
| `test_nodes.py` | ValidateNode/TranslateNode tests |
| `test_nodes_validate.py` | ValidateNode extended tests (consistency check, platform validation) |
| `test_analyzers_{feature}.py` | Per-analyzer tests (15 files) |
| `test_ir.py` | IR translation tests |
| `test_semantic_compare.py` | Semantic validation tests |
| `test_rule_translator.py` | Rule-based fallback tests |
| `test_project_store.py` | Project persistence tests |

## `bench/` — Benchmarks

| File | Role |
|------|------|
| `run_cases.py` | Current runner: static + live, `--tier`, `--cache-test`, JSON report |
| `harness.py` | Legacy harness (deprecated, use `run_cases.py`) |
| `baseline.json` | Historical benchmark baseline |
| `cases/` | 35 JSON case files (routing/switching/firewall) |

## `scripts/` — Operations

| Script | Role |
|--------|------|
| `service.sh` | Unified manager: start/stop/restart/status/logs |
| `start.sh` | Shortcut for `service.sh start` |
| `stop.sh` | Shortcut for `service.sh stop` |
| `restart.sh` | Shortcut for `service.sh restart` |
| `status.sh` | Shortcut for `service.sh status` |
| `release_gate.py` | Quality gate: pytest + lint + coverage + bench |
| `clean_runtime_artifacts.sh` | Remove pycache, pytest cache, semantic caches |

## `docs/` — Documentation

| Doc | Role |
|-----|------|
| `OPERATIONS.md` | Service lifecycle, health checks, troubleshooting |
| `RELEASE_CHECKLIST.md` | 11-step release verification checklist |
| `PROJECT_STRUCTURE.md` | Architecture overview and directory layout |
| `FILE_INDEX.md` | This file — per-file index |
| `REPOSITORY_HISTENE.md` | Cleanup and maintenance guide |
| `analyzers/roadmap.md` | Analyzer implementation roadmap (all phases complete) |
| `analyzers/analyzer_contract.md` | 408-line analyzer interface specification |
| `analyzers/feature_risk_matrix.md` | Risk classification per feature |
| `analyzers/analyzer_plan.json` | 15-analyzer implementation plan |
| `coverage/coverage_matrix.json` | 364-row coverage snapshot |
| `coverage/coverage_matrix.md` | Human-readable coverage table |
| `coverage/benchmark_coverage.md` | Generated benchmark report |

## `frontend/` — Web UI

| File | Role |
|------|------|
| `index.html` | Single-page app: 5 tabs, request_id, copy dropdown, export, risk view |

## Root Config Files

| File | Role |
|------|------|
| `AGENTS.md` | Working instructions for AI agents |
| `CLAUDE.md` | Claude/opencode project configuration |
| `CHANGELOG.md` | Version history |
| `README.md` | Project README with deployment section |
| `VERSION` | Current version label |
| `requirements.txt` | Python dependencies |
| `.env.example` | Environment variable template |
| `llmsetting.example.json` | LLM settings template |

## Planning Documents (Legacy)

| File | Role |
|------|------|
| `plans/domain-vendor-platform-refactor.md` | Phase 4 architecture plan |
| `docs/superpowers/plans/2026-05-16-production-optimization.md` | Phase 5 production optimization plan |

## Runtime Artifacts (gitignored)

| Path | Content |
|------|---------|
| `logs/translator.log` | Service startup/stop/debug |
| `logs/access.log` | Gunicorn HTTP access log |
| `logs/error.log` | Gunicorn error log |
| `logs/translation.jsonl` | Per-request structured log (23 fields) |
| `cache_data/` | LLM response cache |
| `memory_data/events.jsonl` | Translation history |
| `projects/*.json` | Project persistence |
| `.run/translator.pid` | Gunicorn PID file |
| `venv/` | Virtual environment |
| `__pycache__/` | Python bytecode cache |
| `.pytest_cache/` | Pytest cache |
| `llmsetting.json` | Local LLM settings (may contain API keys) |
