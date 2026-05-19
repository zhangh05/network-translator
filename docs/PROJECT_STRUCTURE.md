# Project Structure

This repository implements a Graph-based network configuration translation pipeline.
The architecture is organized into source, knowledge, test, docs, and runtime categories.

## Source Code

```
core/                    29 files — translation pipeline core
├── __init__.py            LLM class (Anthropic + OpenAI compatible), global singleton
├── ir.py                 LLM-driven Intermediate Representation (config→semantic blocks)
├── semantic_compare.py   IR semantic equivalence check (rule-based, no LLM)
├── rule_translator.py    Rule-based fallback translator (no LLM)
├── context.py            GSSC context pipeline
├── graph/
│   ├── base.py           Node/Edge/State base classes
│   ├── nodes.py          ValidateNode, TranslateNode, CapabilityGapNode, etc.
│   └── translation_graph.py  Workflow graph definition
├── analyzers/
│   ├── base.py           FeatureAnalyzer ABC, FeatureAnalysis dataclass
│   ├── registry.py       AnalyzerRegistry (from registry.yaml)
│   ├── __init__.py       Broker, all analyzer imports
│   └── {feature}_analyzer.py  15 analyzers (acl, nat, security_policy, route_policy,
│                               ipsec, qos, address_object, vrrp, dhcp, vrf,
│                               tunnel, bfd, lacp, stp, and fallback NoopAnalyzer)

run.py                    CLI entry point
web_app.py                Flask web service entry point
project_store.py          Project CRUD, translation dispatch, request_id generation
llm_settings.py           LLM model/API settings loader

agents/                   1 file — compatibility wrapper
memory/                   1 file — working/episodic/semantic memory

tools/                    7 files
├── __init__.py           ConfigParser, ConfigDiffer, ConfigValidator, KnowledgeRetriever
├── knowledge_manager.py  IR-driven knowledge retrieval (per-IR-type file cache)
├── knowledge_lint.py     Knowledge file linting and coverage check
├── coverage_inventory.py 364-row coverage matrix scanner
└── gen_bench_cases.py    Benchmark case generator

frontend/
├── index.html            Single-page application (5 tabs + production UX)
└── settings.json         Local UI state (optional)
```

## Knowledge Data

```
knowledge_data/           199 files — the active knowledge base
├── registry.yaml         Feature registry: 44+ features, priority/risk/domains/analyzer
├── capability_map.yaml   Feature→vendor capability mapping (P0+P1, 8 vendors)
├── features/             Feature-specific .md references
├── domains/              Domain-organized knowledge (firewall/routing/switching)
│   └── {domain}/{vendor}/{feature}.md  — Phase 2+ path (takes priority)
├── cisco/                Legacy vendor path (Phase 1, fallback)
├── huawei/               Legacy vendor path (Phase 1, fallback)
└── h3c/                  Legacy vendor path (Phase 1, fallback)
```

Knowledge files: 116 `.md` files, P0 = 179/179 (100%), P1 = 156/165 (94.6%).

## Tests

```
tests/                    31 files — 345 tests
├── test_all.py           Main test suite
├── test_analyzers_*.py   Per-analyzer tests (15 analyzers)
├── test_nodes.py         ValidateNode/TranslateNode tests
├── test_e2e.py           End-to-end translation pipeline
└── conftest.py           Shared fixtures
```

## Benchmarks

```
bench/                    39 files
├── cases/                35 JSON test cases
│   ├── routing/          OSPF, BGP, static, VRF, PBR
│   ├── switching/        VLAN, STP, LACP, interface
│   └── firewall/         NAT, ACL, security-policy, IPsec, zone
├── run_cases.py          Static + live benchmark runner (--tier, --cache-test)
├── harness.py            Legacy benchmark harness (deprecated, use run_cases.py)
├── baseline.json         Historical benchmark baseline
└── harness_results.json  Generated runtime output (gitignored)
```

## Operations and Config

```
scripts/                  7 files
├── service.sh            Unified service manager (start|stop|restart|status|logs)
├── start.sh              Shortcut: service.sh start
├── stop.sh               Shortcut: service.sh stop
├── restart.sh            Shortcut: service.sh restart
├── status.sh             Shortcut: service.sh status
├── release_gate.py       Quality gate: pytest + lint + coverage + benchmark
└── clean_runtime_artifacts.sh  Remove pycache, pytest_cache, semantic caches

.env.example              Environment variable template
llmsetting.example.json   LLM settings template (no real keys)
requirements.txt          Python dependencies (flask, gunicorn, requests, tiktoken)
VERSION                   Current version label
AGENTS.md                 Agent working instructions
CLAUDE.md                 Claude configuration (opencode-compatible)
CHANGELOG.md              Version history
```

## Documentation

```
docs/
├── OPERATIONS.md          Service lifecycle, health checks, troubleshooting
├── RELEASE_CHECKLIST.md   11-step release verification
├── PROJECT_STRUCTURE.md   This file
├── FILE_INDEX.md          File-by-file index
├── REPOSITORY_HYGIENE.md  Cleanup and maintenance guide
├── analyzers/
│   ├── roadmap.md        Analyzer implementation roadmap (all 5 phases complete)
│   ├── analyzer_contract.md  408-line analyzer interface spec
│   ├── feature_risk_matrix.md Risk classification per feature
│   └── analyzer_plan.json    15-analyzer plan
├── coverage/
│   ├── coverage_matrix.json   364-row coverage snapshot
│   ├── coverage_matrix.md     Human-readable coverage table
│   └── benchmark_coverage.md  Generated benchmark report
└── superpowers/
    └── plans/             Historical architecture planning documents
```

## Planning Documents (not source)

```
plans/
└── domain-vendor-platform-refactor.md  38KB Phase 4 architecture plan
```

## Runtime Data (gitignored)

```
logs/                     Service logs + per-request translation.jsonl
cache_data/               LLM response cache
memory_data/              Translation history (JSONL)
projects/                 Project persistence (JSON)
.run/                     PID file
venv/                     Virtual environment
```

## Category Summary

| Category | Files | Description |
|----------|-------|-------------|
| Core source (core/) | 29 | Pipeline engine, graph, analyzers |
| Tools (tools/) | 7 | Parsing, validation, linting, generation |
| Knowledge (knowledge_data/) | 199 | Markdown feature references, registry, capability map |
| Tests (tests/) | 31 | 345 pytest cases |
| Benchmarks (bench/) | 39 | 35 cases + runners |
| Frontend (frontend/) | 2 | Single-page web app |
| Docs (docs/) | 12 | Operations, release, structure, analyzer specs |
| Scripts (scripts/) | 7 | Service management, release gate, cleanup |
| Root files | 12 | Entry points, config, README, VERSION |
| **Total tracked** | **341** | |

## Legacy Indicators

| Path | Status | Notes |
|------|--------|-------|
| `knowledge_data/cisco/`, `huawei/`, `h3c/` | Legacy (compatible) | Phase 1 paths; `domains/` path takes priority |
| `bench/harness.py` | Deprecated | Use `run_cases.py` instead |
| `plans/` | Planning docs | Historical, not active source |
| `docs/superpowers/` | Planning docs | Historical, not active source |
