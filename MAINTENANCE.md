# Maintenance Runbook

## Service Lifecycle

```bash
./scripts/start.sh          # Start (port 5008 default)
./scripts/stop.sh           # Graceful stop
./scripts/restart.sh        # Restart
./scripts/status.sh         # Health check
./scripts/service.sh logs   # Tail logs
```

Health endpoints:
- `GET /healthz` — liveness (`{"ok":true}`)
- `GET /readyz` — readiness (checks VERSION, knowledge_data, LLM_API_KEY, memory_data, analyzers)

## Configuration

| Variable | Purpose | Default |
|----------|---------|---------|
| `LLM_API_KEY` | API key for LLM | required |
| `LLM_MODEL` | Model name | `MiniMax-M2.7` |
| `LLM_BASE_URL` | LLM endpoint | required |
| `LLM_TIMEOUT` | HTTP timeout (s) | `45` |
| `LLM_FALLBACK_API_KEY` | Fallback provider key | optional |
| `LLM_FALLBACK_BASE_URL` | Fallback provider URL | optional |
| `LLM_FALLBACK_MODEL` | Fallback model | optional |
| `API_SECRET` | API auth secret | optional |
| `PORT` | HTTP port | `5008` |

Via UI: Settings dialog (`...` button in toolbar) persists to `llmsetting.json`.

## Testing

```bash
pytest -q                           # Unit tests (~440, ~3s)
python tools/validate_corpus.py     # Corpus data governance (IP, credentials, schema)
python tools/corpus_to_bench.py --dry-run  # Corpus → bench cases
python bench/run_cases.py --static-only    # Static bench
python bench/run_cases.py --static-only --corpus-only  # Corpus bench
python scripts/release_gate.py             # Pre-release gate
```

Live tests (require running service + configured LLM):
```bash
BENCH_TIMEOUT=180 python bench/run_cases.py \
  --api-base http://127.0.0.1:5008 \
  --domain corpus \
  --live-report-json bench/live_report.json
python tools/live_failure_backlog.py bench/live_report.json
```

## Reports & Coverage

```bash
python tools/generate_coverage_matrix.py  # → reports/coverage_matrix.{md,json}
python tools/validate_corpus.py --report  # → reports/corpus_validation.md
```

## Monitoring

- **translation log**: `logs/translation.jsonl` — every request with request_id, vendor, domain, analyzer findings, validation, deployability, elapsed_ms
- **failed requests**: `logs/translation.jsonl` — filter `success:false` or `validation_level:fatal`
- **risk signals**: `risk_signals` field in API response and log entries — shows each risk decision with severity, feature, message
- **provider health**: `LLM` object `_fallback.summary()` — circuit breaker states per provider
- **memory**: `memory_data/` — working memory files; delete to reset

## Failure Diagnosis

| Symptom | Likely Cause | Action |
|---------|-------------|--------|
| `LLM API key missing` | `LLM_API_KEY` not set | Check env / UI settings |
| `LLM base URL missing` | `LLM_BASE_URL` not set | Check env / UI settings |
| `unrecognized LLM response` | API response format mismatch | Check model compatibility |
| `LLM 输出校验失败` | LLM returned invalid output | Check prompt version / model quality |
| Circuit breaker OPEN | Provider repeatedly failing | Check provider URL/key; auto-recovers after cooldown |
| `TRANSLATION_INTERNAL_ERROR` | Graph node exception | Check logs for traceback |
| `EMPTY_CONFIG` | Empty request body | Client error |
| No translation with 10+ chars | Translation too short / failed | Check fallback_reason, node_results |

## LLM Output Validation

`core/ir.py` contains `validate_and_repair_llm_output()` which:
- Strips Markdown fences
- Extracts JSON from surrounding text
- Validates required fields (`type`, `translated_lines`, `original_lines`, `notes`, `confidence`)
- Detects placeholders (`<...>`, `TODO`, `PLACEHOLDER`)
- Detects source vendor residue
- Repairs minor issues (missing fields, fence nesting)
- Returns repair metadata via `_meta` blocks

Prompt version tracked in `core/ir.py:PROMPT_VERSION`. Each prompt call includes `prompt_version: <version>` in the prompt text, and the version is recorded in output `_meta`.

## Provider Fallback

If `LLM_FALLBACK_BASE_URL` is set, `LLM` automatically configures a `ProviderFallback` with both primary and fallback providers. Circuit breaker opens after 3 consecutive failures, cools down for 60s, then half-opens. Status available via `_fallback.summary()`.

## Corpus Management

- Sanitized configs: `corpus/sanitized/` — must use RFC 1918 / documentation IPs only
- Annotations: `corpus/annotations/` — one per sanitized config
- Schema: `corpus/schema.json`
- Validate: `python tools/validate_corpus.py` (checks IP hygiene, credentials, schema, file consistency, feature names)
- Generate bench cases: `python tools/corpus_to_bench.py`
- Coverage matrix: `python tools/generate_coverage_matrix.py`

Do not commit real customer configurations or credentials. Log entries contain config hashes/snippets only.

## Release

1. `python tools/validate_corpus.py` — corpus data governance
2. `pytest -q` — unit tests pass
3. `python tools/corpus_to_bench.py --dry-run` — bench generation
4. `python bench/run_cases.py --static-only --corpus-only` — static bench
5. `python scripts/release_gate.py --mode release` — automated gate
6. Update `VERSION` file
7. Restart service: `./scripts/restart.sh`

## Live Corpus Verification

Requires `LLM_API_KEY` in environment and a running service.

```bash
BENCH_TIMEOUT=180 python bench/run_cases.py \
  --api-base http://127.0.0.1:5008 \
  --domain corpus \
  --live-report-json bench/live_report.json

python tools/live_failure_backlog.py
```

**Current status (as of 2026-05-20): BLOCKED** — LLM_API_KEY not available in this
environment. The stale baseline at `bench/live_report.json` (13/15) was generated
before the P0/P1 risk model changes and cannot be used as a quality indicator.
Regenerate after obtaining a valid LLM key.

Expected output files:
- `bench/live_report.json` — per-case live translation results
- `reports/live_failure_backlog.md` — categorized failure report

Do not release until live corpus passes (or explicit waiver with documented
acceptance criteria).

## Architecture Overview

DAG nodes (execution order):
```
ParseNode → FeatureAnalyzerNode → KnowledgeNode → CacheNode →
TranslateNode → RouterNode/FallbackNode → SemanticValidatorNode →
CapabilityGapNode → ValidateNode → DiffNode → CacheWriteNode → MemoryNode
```

Key files:
- `web_app.py` — API + frontend
- `project_store.py` — project persistence + run entrypoint
- `core/graph/agent.py` — GraphAgent orchestrator
- `core/graph/translation_graph.py` — DAG + flow executor
- `core/graph/nodes.py` — node implementations
- `core/ir.py` — LLM prompts + output validation
- `core/risk_decision.py` — deployability risk model
- `core/provider_fallback.py` — circuit breaker + fallback
- `core/analyzers/` — feature-specific analyzers
- `knowledge_data/` — feature knowledge, capability map, profiles
