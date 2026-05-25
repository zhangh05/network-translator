# Runbook

> Phase 8D — 2026-05-25 (Batch I-J: Beta acceptance documented)

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

**Listen address**: `0.0.0.0:5008` by default.

- Local access: `http://127.0.0.1:5008`
- LAN access: `http://<this-mac-ip>:5008`
- Local-only mode: `HOST=127.0.0.1 ./scripts/service.sh start`
- Trusted intranet deployments can leave `HOST=0.0.0.0`; set `API_SECRET` if the service is exposed beyond a trusted network.

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

### Beta acceptance doc consistency
```bash
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_beta_acceptance_docs.py -v
```

### Output redaction tests
```bash
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_output_redaction.py -v
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
- The web service listens on `0.0.0.0` by default for intranet access; use `HOST=127.0.0.1` when you only want local access
- If exposing the service outside a trusted intranet, set `API_SECRET` and put it behind an authenticated reverse proxy
- Do not add any download/static route for `llm_settings.txt`, `llmsetting.json`, or other secret files

### Testing the Configuration

```python
from llm_settings import get_current_settings, mask_api_key

cfg = get_current_settings()
print(f"API key (safe): {mask_api_key(cfg['api_key'])}")  # prints ***
print(f"Model: {cfg['model']}")   # safe to print
print(f"Base URL: {cfg['base_url']}")  # safe to print
```
| `PORT` | No | `5008` | Web server port |
| `HOST` | No | `0.0.0.0` | Web server listen address; use `127.0.0.1` for local-only access |
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

## Beta Acceptance

Full Beta acceptance package: **[docs/BETA_ACCEPTANCE_2026-05-25.md](./BETA_ACCEPTANCE_2026-05-25.md)**
Machine-readable summary: **[docs/beta_acceptance_2026_05_25.json](./beta_acceptance_2026_05_25.json)**

### Current verdict
```
BETA_READY = YES (conditional)
```
- ✅ CI gate pass: 1254 passed, 0 regressions
- ✅ Output redaction P0 resolved (all API paths)
- ⚠️ **Primary blocking**: GitHub Actions runner not yet validated
- ⚠️ 13 known tolerated failures not yet resolved

## Pre-existing Failure Tolerances

See `docs/CI_QUALITY_GATES.md` for the authoritative list.

As of 2026-05-25:
- 13 known failures (deprecated analyzer + missing flask/requests in dev)
- CI with full deps: ~7 known failures (test_analyzer_object only)
- All tolerated in Layer 2 gate; Layer 1 core gate is zero-tolerance

## Common Operations

### Check service health
```bash
curl --noproxy '*' http://localhost:5008/healthz
```

### Check readiness
```bash
curl --noproxy '*' http://localhost:5008/readyz
```

### Check version
```bash
curl --noproxy '*' http://localhost:5008/api/version
```

### Create a translation project
```bash
curl --noproxy '*' -s -X POST http://localhost:5008/api/projects \
  -H "Content-Type: application/json" \
  -d '{"name":"my-project"}'
```

### Run translation
```bash
curl --noproxy '*' -s -X POST http://localhost:5008/api/projects/<pid>/translate \
  -H "Content-Type: application/json" \
  -d '{"source_config":"...","source_vendor":"h3c","target_vendor":"cisco"}'
```

### API Key Required (if API_SECRET is set)
```bash
curl -H "X-API-Secret: <your-secret>" ...
```

## Browser Acceptance Testing

### Starting the service

The service requires Flask, which is installed in `.venv-local` (not `venv`):
```bash
# Using the project's service script (uses .venv-local automatically)
PORT=5008 ./scripts/start.sh

# Or directly with .venv-local
PORT=5008 .venv-local/bin/python web_app.py
```

Verify service is running:
```bash
curl --noproxy '*' http://127.0.0.1:5008/healthz
```

Expected: `{"ok":true,"status":"healthy"}`

### Access addresses

- Local: `http://127.0.0.1:5008`
- LAN: `http://<machine-lan-ip>:5008` (e.g. `http://192.168.5.x:5008`)
- The service listens on `0.0.0.0:5008` by default

### Manual acceptance steps

1. Open browser to `http://127.0.0.1:5008`
2. Create/rename project window via sidebar
3. Select source vendor (e.g. Huawei) and target vendor (e.g. Cisco)
4. Paste configuration text
5. Click 翻译 button
6. After translation completes, check:
   - **translated tab**: Always shows `deployable_config` (deterministic rule-based output when fallback is used)
   - **risk tab**: Shows fallback notice (if fallback) + Chinese category risk analysis
   - **validation tab**: Shows deployability status and error/warning counts
   - **diff tab**: Shows source vs target config diff
7. Click 复制 dropdown:
   - **复制全部配置**: Copies `deployable_config` (or `translated` if deployable is empty)
   - **复制可部署配置**: Copies `deployable_config` with `# MANUAL_REVIEW` lines removed
   - **复制风险报告**: Copies structured text report with validation/capability gaps
8. Refresh browser — result should persist
9. Open new browser window — same project should be visible

### Fallback report visibility

When fallback is triggered (LLM output validation failed):
- **translated tab** shows `deployable_config` (deterministic rule-based output), not the fallback report
- **risk tab** shows a fallback notice directing user to "请重点查看：人工复核摘要、可部署配置、风险报告"
- `人工复核摘要` appears in the **risk tab** via the fallback notice and Chinese category analysis, not in the translated tab
- `MANUAL_REVIEW` lines (if any in `deployable_config`) are highlighted in the translated tab

### If results disappear after refresh

Check project persistence:
```bash
# List projects
curl --noproxy '*' http://127.0.0.1:5008/api/projects

# Get specific project
curl --noproxy '*' http://127.0.0.1:5008/api/projects/<project-id>
```

Verify `result` field is not null and contains `deployable_config`.

### If copy content is wrong

The three copy modes pull from different fields:

| Copy mode | Source field | Notes |
|-----------|-------------|-------|
| 复制全部配置 | `deployable_config \|\| translated` | Prefers deployable |
| 复制可部署配置 | `deployable_config` | Filters out `# MANUAL_REVIEW` lines |
| 复制风险报告 | Constructed from `validation`, `risk_signals`, `capability_gaps`, `analyzer_results` | Never includes raw config |

Check browser DevTools → Network tab → translate API response to verify `deployable_config` field is present and correct.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `ModuleNotFoundError: No module named 'flask'` | Missing dependencies | `pip install -r requirements.txt` |
| `LLM_API_KEY not set` | Missing env var | Set `LLM_API_KEY=sk-...` |
| Tests fail with `requests` errors | Missing requests lib | `pip install requests` |
| Service won't start (port in use) | Port conflict | Change `PORT` env or kill existing process |
| Pre-existing failures unexpectedly increase | Regression in extended tests | Run `scripts/ci_quality_gates.py --full` to compare |
