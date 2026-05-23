# Operations Guide

## Service Lifecycle

```bash
./scripts/start.sh          # Start the service
./scripts/stop.sh           # Graceful stop
./scripts/restart.sh        # Restart
./scripts/status.sh         # Check status (pid, port, healthz, readyz, version)
./scripts/service.sh logs   # Tail translator.log
```

## Default Configuration

| Setting  | Default | Env var |
|----------|---------|---------|
| Port     | 5008    | `PORT`  |
| Host     | 0.0.0.0 | `HOST`  |
| Workers  | 4       | `WORKERS` |
| Gunicorn timeout | 600s | `GUNICORN_TIMEOUT` |

Override via environment variables:

```bash
PORT=8080 WORKERS=2 ./scripts/start.sh
```

Or via `.env` file (loaded by the shell before running scripts):

```bash
cp .env.example .env
vim .env
./scripts/start.sh
```

`scripts/service.sh` automatically loads `.env` before starting or checking the
service. When `HOST=0.0.0.0`, health checks probe `127.0.0.1` by default; set
`PROBE_HOST` only if the local probe address is different.

## Health Checks

| Endpoint | Purpose | Expected |
|----------|---------|----------|
| `GET /healthz` | Liveness — is the process alive | `{"ok":true,"status":"healthy"}` |
| `GET /readyz` | Readiness — can it accept requests | `{"ok":true,"status":"ready"}` or `"ready"` with warnings |
| `GET /api/version` | Version info | `{"version":"...","analyzers":13,"features":44,"model":"...","python":"..."}` |

### readyz Warning States

`readyz` returns `status: "ready"` even when some components are degraded.
Check the `warnings` array for details:

| Warning | Meaning | Impact |
|---------|---------|--------|
| `LLM_API_KEY not set` | No API key configured | Falls back to rule-based translation (limited coverage) |
| Other warnings | Optional component unavailable | Varies per component |

The response also includes a `checks` object with machine-readable runtime
signals such as `llm_configured`, `feature_registry_loaded`, `analyzers_loaded`,
and `settings_file_private`.

### Long Translation Requests

Large device configs can take several minutes because the service performs a
single LLM translation call and the LLM client may retry provider requests.
Keep `GUNICORN_TIMEOUT` at least `LLM_TIMEOUT * 3 + 30`; with the default
`LLM_TIMEOUT=180`, the service default is `GUNICORN_TIMEOUT=600`.

## Logging

### Log Files

All logs are under `logs/`:

| File | Content |
|------|---------|
| `logs/translator.log` | Service startup/stop/debug messages |
| `logs/access.log` | Gunicorn HTTP access log (when using gunicorn) |
| `logs/error.log` | Gunicorn error log (when using gunicorn) |
| `logs/translation.jsonl` | Per-translation structured log |

### translation.jsonl — Per-Request Log

Every translation request writes one JSON line to `logs/translation.jsonl`:

```json
{
  "request_id": "d1920d6a-a04e-4d41-a542-65f1fe0a8ed2",
  "timestamp": "2026-05-19T12:34:56.789012",
  "version": "v11-phase4-coverage-risk",
  "model": "MiniMax-M2.7",
  "elapsed_ms": 1234.5,
  "source_domain": "enterprise",
  "source_vendor": "huawei",
  "source_platform": "CE12800",
  "target_domain": "enterprise",
  "target_vendor": "cisco",
  "target_platform": "IOS-XE",
  "config_hash": "sha256:abc123...",
  "config_snippet": "interface GigabitEthernet0/0/1\n  port link-type trunk...",
  "success": true,
  "cache_hit": false,
  "fallback_used": false,
  "route_decision": "llm",
  "features": ["vlan","interface"],
  "node_results": [...],
  "capability_gaps": [],
  "validation_level": "info",
  "deployable": true,
  "manual_review_required": false,
  "warning_count": 0,
  "error_count": 0,
  "error_reason": ""
}
```

Note: The log contains a SHA-256 hash of the config (not the raw config),
and only the first 120 characters of the config as a snippet.
No API keys are ever logged.

## Troubleshooting with request_id

Every response includes a `request_id` field (UUID). To find the corresponding log entry:

```bash
grep "<request_id>" logs/translation.jsonl | python3 -m json.tool
```

This shows you the full execution context: timing, features detected, validation
results, capability gaps, and node-level timing breakdown.

## Runtime Data

| Directory | Purpose | When to Clear |
|-----------|---------|---------------|
| `memory_data/` | Translation history (JSONL) | Safe to clear; no impact on service |
| `cache_data/` | LLM response cache | Clear to force fresh translations |
| `logs/` | Service and translation logs | Rotate or clear as needed |
| `.run/` | PID file | Auto-cleaned on stop |

To clear caches:

```bash
rm -rf cache_data/* memory_data/*
```

## Running Checks

### Release Gate

```bash
PYTHONPATH=. python3 scripts/release_gate.py
```

Runs: pytest, knowledge_lint, coverage check, benchmark verification.
Returns `RELEASE_GATE_OK` if all pass.

### Benchmarks

```bash
# Static benchmarks (no LLM required)
PYTHONPATH=. python3 bench/run_cases.py --static

# Live benchmarks (requires LLM_API_KEY + running service)
PYTHONPATH=. python3 bench/run_cases.py --live

# Filter by tier
PYTHONPATH=. python3 bench/run_cases.py --static --tier smoke
PYTHONPATH=. python3 bench/run_cases.py --static --tier core
PYTHONPATH=. python3 bench/run_cases.py --static --tier full
```

### Nightly Smoke Test

```bash
./scripts/status.sh                        # service running?
curl --noproxy '*' http://localhost:5008/healthz   # liveness
curl --noproxy '*' http://localhost:5008/readyz    # readiness
curl --noproxy '*' http://localhost:5008/api/version  # version info
PYTHONPATH=. python3 scripts/release_gate.py       # full gate
```

## Common Issues

### Port already in use

```bash
ss -tlnp | grep :5008    # find what is using the port
# kill the process if it's an orphaned translator
kill <pid>
```

### LLM_API_KEY not set

The service starts fine but will use rule-based translation only.
Check `/readyz` for the warning. Set `LLM_API_KEY` and restart.

### LLM returns empty response

Causes: network timeout, invalid API key, model overload.

1. Check `logs/error.log` or `logs/translator.log`
2. Verify `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL` are correct
3. Increase `LLM_TIMEOUT` (default 45s)
4. Re-translate — the result will fall back to rule-based translation

### request_id not found in translation.jsonl

Possible causes:
- Translation failed before the log entry was written
- Log file was rotated/cleared
- Wrong file (the request_id appears in `logs/translation.jsonl`, not `error.log`)

```bash
grep "<request_id>" logs/translation.jsonl
```

### deployable=false — What This Means

When a translation result has `deployable: false`, it means automated checks
detected one or more issues:

| Scenario | Likely Cause |
|----------|--------------|
| Source-vendor residue in output | LLM left Cisco commands in output meant for Huawei |
| High-risk feature missing | NAT/ACL/IPsec/route-policy/security-policy not translated |
| Syntax validation error | Output fails target-vendor syntax check |
| Placeholders detected | LLM used `<angle-bracket>` or TODO placeholders |

Translation is still returned for reference, but manual review is required
before deploying to production.

## Cleaning Runtime Artifacts

```bash
./scripts/clean_runtime_artifacts.sh
```

Removes: `__pycache__`, `.pyc`, `.pytest_cache`, semantic caches.
