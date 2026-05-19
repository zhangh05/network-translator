# Project Structure

This repository is organized around a Graph-based network configuration translation pipeline.

## Runtime Entry Points

- `web_app.py` starts the Flask application and serves `frontend/index.html`.
- `run.py` starts the interactive CLI.
- `project_store.py` owns project CRUD routes and calls the Graph translator for project translations.
- `llm_settings.py` owns model/API settings and constructs the shared LLM client.

## Translation Core

- `agents/` contains the compatibility wrapper used by older benchmark and tool-call code.
- `core/graph/` contains the executable workflow: parse, knowledge, translate, semantic validation, syntax validation, diff, fallback, and memory.
- `core/ir.py` contains the LLM-driven intermediate representation prompts and JSON parsing helpers.
- `tools/` contains configuration parsing, validation, diffing, and knowledge retrieval helpers.
- `memory/` contains working, episodic, and semantic memory implementations.

## Knowledge Sources

- `knowledge_data/` is the active Markdown knowledge base used by the IR translation flow.
- `knowledge_new/` contains newer or imported command references that can be promoted into `knowledge_data/`.
- `knowledge/` is the legacy JSON knowledge location; old compatibility helpers can still read it when present.

## Tests And Benchmarks

- `tests/` contains pytest regression and capability tests for the current code.
- `bench/` contains benchmark harnesses and historical benchmark output.

## Runtime Data And Generated Files

These directories/files are local runtime state and should not be treated as source:

- `venv/`
- `__pycache__/`
- `.pytest_cache/`
- `memory_data/`
- `projects/`
- `llmsetting.json`

If these paths are already tracked by git in an older checkout, `.gitignore` will prevent new noise but will not remove existing tracked entries. Clean-up should be done separately and deliberately.
