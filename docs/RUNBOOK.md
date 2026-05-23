# Runbook

> Phase 8D — 2026-05-23

## Service Management

```bash
# Start (prefers gunicorn, falls back to flask dev server)
./scripts/start.sh

# Stop
./scripts/stop.sh

# Restart
./scripts/restart.sh

# Status
./scripts/status.sh

# View logs
./scripts/service.sh logs

# Clean runtime artifacts (memory, temp files)
./scripts/clean_runtime_artifacts.sh
```

**Port**: 5000 (configurable via `PORT` env variable)

## Running Tests

### Quick check (Layer 1 — core gate, ~0.4s)
```bash
PYTHONPATH=. python3 scripts/ci_quality_gates.py
```

### Full check (all layers, ~2s)
```bash
PYTHONPATH=. python3 scripts/ci_quality_gates.py --full
```

### Full test suite
```bash
PYTHONPATH=. venv/bin/python3 -m pytest tests/ -v
```

### Specific modules
```bash
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_validator*.py -v --tb=short
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_integration_phase6.py -v
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_integration_phase7.py -v
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_schema_contract.py -v
```

### Performance baseline
```bash
PYTHONPATH=. python3 scripts/run_baseline.py
```

### Audit traceability drill
```bash
PYTHONPATH=. bash scripts/audit_trace.sh
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LLM_API_KEY` | Yes | — | LLM API key for translation |
| `LLM_MODEL` | No | `MiniMax-M2.7` | LLM model name |
| `LLM_BASE_URL` | No | — | Custom LLM endpoint |
| `LLM_TIMEOUT` | No | `45` | LLM request timeout (seconds) |
| `LLM_SETTINGS_FILE` | No | — | Explicit path to a JSON settings file |
| `API_SECRET` | No | — | If set, all API endpoints require `X-API-Secret` header |

## LLM Configuration Files

Settings are loaded from multiple sources in priority order:

| Priority | Source | Path | Notes |
|----------|--------|------|-------|
| 1 (highest) | `LLM_SETTINGS_FILE` env var | Path in env var | Explicit path; supersedes all others |
| 2 | External settings file | `/Users/zhangh01/Desktop/codex_net_trans/llm_settings.txt` | Developer-machine-local; not committed |
| 3 | Project-local settings | `network-translator/llmsetting.json` | In-source; tracked in git |
| 4 (lowest) | Environment variable fallbacks | `LLM_API_KEY`, `LLM_MODEL`, `LLM_BASE_URL`, `LLM_TIMEOUT` | Always honored as final fallback |

### External Settings File Format

The external settings file (`llm_settings.txt`) must contain valid JSON:

```json
{
  "api_url": "https://api.minimaxi.com/anthropic",
  "api_key": "sk-your-key-here",
  "model": "Minimax M2.7",
  "timeout": 60
}
```

Field mapping:
- `api_url` → `base_url` internally
- `api_key` → stored as-is; **never logged in plain text**
- `model` → whitespace-stripped; case-insensitive

### Security Notes

- API keys are **never printed in logs** — only `***` or `(not set)` is shown
- The external settings file (`/Users/zhangh01/Desktop/codex_net_trans/llm_settings.txt`) should NOT be committed to source control
- Use `llm_settings.mask_api_key()` to safely display any key value

### Testing the Configuration

```python
from llm_settings import get_current_settings, mask_api_key

cfg = get_current_settings()
print(f"API key (safe): {mask_api_key(cfg['api_key'])}")  # prints ***
print(f"Model: {cfg['model']}")   # safe to print
print(f"Base URL: {cfg['base_url']}")  # safe to print
```
| `PORT` | No | `5000` | Web server port |
| `FLASK_DEBUG` | No | — | Enable Flask debug mode |

## Directory Layout

```
network-translator/
├── core/               # Core modules (domain, vendor, IR, validator, parser, renderer, batch)
├── tests/              # All test files
├── tools/              # Utility scripts (config parser, differ, knowledge manager)
├── knowledge_data/     # Vendor-specific knowledge base (.md files)
├── scripts/            # Operational scripts (start/stop, CI gates, audit, baseline)
├── docs/               # Documentation
│   ├── audit/          # Unified archive (symlinks + trace records)
│   ├── coverage/       # Coverage matrix
│   └── ...
├── memory_data/        # LLM memory traces (events.jsonl)
├── projects/           # Project store data
├── AGENTS.md           # Architecture guide
├── RUNBOOK.md          # This file
└── VERSION             # Current version label
```

## Pre-existing Failure Tolerances

See `docs/CI_QUALITY_GATES.md` for the authoritative list.

As of 2026-05-23:
- 13 known failures (deprecated analyzer + missing flask/requests in dev)
- CI with full deps: ~7 known failures (test_analyzer_object only)
- All tolerated in Layer 2 gate; Layer 1 core gate is zero-tolerance

## Common Operations

### Check service health
```bash
curl --noproxy '*' http://localhost:5000/healthz
```

### Check readiness
```bash
curl --noproxy '*' http://localhost:5000/readyz
```

### Check version
```bash
curl --noproxy '*' http://localhost:5000/api/version
```

### Create a translation project
```bash
curl --noproxy '*' -s -X POST http://localhost:5000/api/projects \
  -H "Content-Type: application/json" \
  -d '{"name":"my-project"}'
```

### Run translation
```bash
curl --noproxy '*' -s -X POST http://localhost:5000/api/projects/<pid>/translate \
  -H "Content-Type: application/json" \
  -d '{"source_config":"...","source_vendor":"h3c","target_vendor":"cisco"}'
```

### API Key Required (if API_SECRET is set)
```bash
curl -H "X-API-Secret: <your-secret>" ...
```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `ModuleNotFoundError: No module named 'flask'` | Missing dependencies | `pip install -r requirements.txt` |
| `LLM_API_KEY not set` | Missing env var | Set `LLM_API_KEY=sk-...` |
| Tests fail with `requests` errors | Missing requests lib | `pip install requests` |
| Service won't start (port in use) | Port conflict | Change `PORT` env or kill existing process |
| Pre-existing failures unexpectedly increase | Regression in extended tests | Run `scripts/ci_quality_gates.py --full` to compare |
