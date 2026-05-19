# File Index

Last updated: 2026-05-16

## Top-level

- `agents/`: agent entry layer and compatibility wrapper.
- `bench/`: benchmark harness and baseline history.
- `core/`: graph workflow and translation core modules.
- `docs/`: project documentation and maintenance notes.
- `scripts/`: maintenance and release scripts.
- `tests/`: regression and capability tests.
- `tools/`: parser, validator, differ, and knowledge utilities.
- `run.py`: CLI entry.
- `web_app.py`: web service entry.
- `project_store.py`: project/session persistence and API routes.

## Generated/Runtime Artifacts (not source of truth)

- `bench/harness_results.json`: generated benchmark output.
- `memory_data/`: runtime translation history.
- `projects/`: runtime project snapshots.
- `__pycache__/`, `*.pyc`, `.pytest_cache/`: runtime caches.

## Cleanup Rules

- Keep `bench/baseline.json` (historical quality trend).
- Clean caches (`__pycache__`, `*.pyc`, `.pytest_cache`) regularly.
- Do not commit runtime state (`memory_data`, `projects`, benchmark outputs).

## Service Control

- `scripts/service.sh`: unified service manager (`start|stop|restart|status|logs`)
- `scripts/start.sh`: shortcut to start service
- `scripts/stop.sh`: shortcut to stop service
- Runtime files:
  - PID: `.run/translator.pid`
  - Log: `logs/translator.log`
