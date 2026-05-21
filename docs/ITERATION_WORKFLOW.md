# Iteration Workflow

## One Complete Remediation Loop

### Phase 7: Corpus Flywheel
```
raw → sanitized → annotation → validate → bench → live → backlog → fix → gate → document
```
Each new config follows: collect, sanitize, annotate, validate, bench case, live test, fix failures, document.

### Phase 8: Automation Layer
After manual loop stabilizes, use scripts:
- `scripts/run_iteration.sh quick` — quick gate check
- `scripts/run_iteration.sh full` — full gate check  
- `tools/live_failure_backlog.py` — live report → backlog
- `scripts/project_status.sh` — full status dump

### Phase A: Collect & Sanitize
```
corpus/raw/ → corpus/sanitized/
```
- Redact IPs to 198.18.x.x
- Redact passwords/secrets to __REDACTED__
- Run: `python tools/validate_corpus.py`

### Phase B: Annotate
```
corpus/sanitized/ → corpus/annotations/*.annotation.json
```
- Add classification (vendor/domain/features/risk)
- Add expected_translation (target vendor, key_lines, must_not_contain)
- Add verification (deployable/manual_review_required/notes)
- Run: `python tools/validate_corpus.py`

### Phase C: Generate Bench Cases
```
corpus/annotations/ → bench/cases/corpus/
```
- Run: `python tools/corpus_to_bench.py`
- Run: `python bench/run_cases.py --corpus-only --static-only`

### Phase D: Live Batch
```
bench/cases/corpus/ → bench/live_report.json
```
- Run: `python bench/run_cases.py --corpus-only --live-report-json bench/live_report.json`
- Requires: LLM_API_KEY, gunicorn running on :5008
- Alternative: use existing live_report.json if API unavailable

### Phase E: Generate Backlog
```
bench/live_report.json → reports/live_failure_backlog.md
```
- Run: `python tools/live_failure_backlog.py bench/live_report.json`

### Phase F: Remediate
1. Pick highest-priority cluster from backlog (P0 first)
2. Classify failure: annotation_issue / knowledge_gap / prompt_issue / validator_* / analyzer_gap / llm_quality_issue
3. Make minimal fix
4. Update tests
5. Run gates: pytest, corpus_validate, corpus_to_bench, static bench

### Phase G: Verify & Handoff
- Update TASK_HANDOFF.md
- Update docs/coverage/live_corpus_remediation_X.md
- Run: `scripts/project_status.sh` (or `scripts/run_iteration.sh`)

## Quick Iteration (single command)
```bash
scripts/run_iteration.sh quick
```

## Full Iteration (with live)
```bash
scripts/run_iteration.sh full
python bench/run_cases.py --corpus-only --live-report-json bench/live_report.json
python tools/live_failure_backlog.py bench/live_report.json
```

## Gate Checklist
- [ ] pytest: targeted tests pass
- [ ] corpus_validate: 0 errors, 0 warnings
- [ ] corpus_to_bench: all entries generated
- [ ] static bench corpus: 100% pass
- [ ] live batch: runs without crash
- [ ] backlog generated
- [ ] TASK_HANDOFF.md updated
