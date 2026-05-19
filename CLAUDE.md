# CLAUDE.md

This file provides fast, current guidance for agents working in this repository.

## Project Overview

Network-Translator-Agent is a Graph-based network configuration translator.
It targets semantic equivalence across Cisco, Huawei, H3C, and Ruijie style configs.

Primary path:
`parse -> knowledge -> translate(IR) -> semantic_validate -> validate -> diff -> memory`

## Runbook

```bash
# CLI
python3 run.py

# Web
python3 web_app.py

# Current tests
python3 -m pytest -q

# Bench harness
python3 bench/harness.py

# Release gate (tests + knowledge lint + benchmark threshold)
python3 scripts/release_gate.py
```

## Architecture Notes

- `core/graph/`: workflow engine and graph nodes.
- `core/ir.py`: LLM-driven IR parse/translate/compare with JSON safety checks.
- `core/rule_translator.py`: deterministic fallback translator for high-frequency commands.
- `tools/__init__.py`: parser/validator/diff/legacy knowledge retrieval helpers.
- `knowledge_data/`: active Markdown knowledge base.
- `project_store.py`: project CRUD routes and translation orchestration.

## API Notes

- `POST /api/projects/<project_id>/translate`: translate within a stored project.
- `POST /api/translate`: one-shot translation API.
- `GET /healthz`, `GET /readyz`: health/readiness.

## Known Production Gaps

- Rule fallback does not yet fully cover all advanced features (for example full NAT/AAA/QoS matrices).
- Knowledge base needs continuous coverage expansion and lint enforcement in CI.
- Repository still contains historical tracked runtime noise; cleanup should be done in a dedicated git hygiene pass.
