# Known Limitations

## NAT Translation Flakiness

### Problem
Cisco ASA ↔ Huawei VRP NAT translations are non-deterministic due to LLM output quality variance:

| Case | Direction | Clean deployable rate | Notes |
|------|-----------|----------------------|-------|
| fw-nat-001 | Huawei→Cisco ASA | ≈85% (3/3 in recent batch) | LLM may add `MANUAL_REVIEW` about interface/syntax mapping. Validator correctly blocks. RC4 prompt fix added positive alternatives for ASA→VRP object-network mapping. |
| fw-nat-server-001 | Cisco ASA→Huawei | ≈30% (0/3 in recent batch) | LLM adds MANUAL_REVIEW about nameif/security-level mapping + `object network` residue. RC4 prompt/knowledge fix adds nameif→firewall-zone and security-level→priority mapping guidance. |
| fw-ipsec-vpn-001 | Cisco ASA→Huawei | ≈30% (0/3 in recent batch, passed previously) | LLM outputs `object network` residue in VRP IPsec output. RC4 prompt/knowledge fix adds ACL mapping alternatives for object-network in IPsec context. |

### Mitigation
- **Validator**: `has_platform_residue` correctly blocks cross-vendor command leakage (deployability_impact gate ensures style warnings don't trigger false negatives).
- **Prompt constraints**: `_asa_nat_rule()` explicitly forbids `security-policy`/`security-zone` in ASA output; `_no_cisco_asa_in_vrp()` forbids `object-network`/`nameif`/`access-group` in VRP output.
- **Annotation**: NAT server cases expected `manual_review_required=true`; live correctness judged by validator's ability to identify need for review, not by clean deployable rate.
- **Risk acceptance**: These cases are inherently hard for LLMs due to platform-specific NAT semantics. The validator chain correctly catches failures.

### Resolution Path
- Longer-term: fine-tune or example-augment the LLM for NAT-specific scenarios.
- Short-term: prompt/knowledge improvements (ongoing).

## Semantic Comparison Accuracy

### Problem
The rule-based `SemanticComparator` uses keyword overlap matching (IR block comparison) which can report false negatives (`score: 0.0`) even when the translated output is correct. This is because ASA-style output (`access-group`, `object-group network`, `nat (inside,outside)`) uses different keywords than Huawei source (`security-policy`, `ip address-set`, `nat source`).

### Impact
Low — the semantic comparison score is logged but does not gate deployability. The `ValidateNode` uses independent rule-based checks (residue, forbidden patterns, must_include, reference validation) which are more reliable.

### Resolution Path
Planned: migrate to LLM-based semantic comparison (`compare_ir()`) as the primary validator, with rule-based checks as a secondary gate.

## HTTP 500 / Gunicorn Worker Timeout

### Problem
`llmsetting.json` has `"timeout": 180` (LLM client timeout). If gunicorn `--timeout` is less than 180s, a slow LLM request can exceed the gunicorn worker timeout before the LLM client timeout fires, causing HTTP 500.

**RC4 fix**: `scripts/service.sh` now defaults `GUNICORN_TIMEOUT=240`. This gives LLM up to 180s + network overhead before worker restart.

### Production Configuration Rules
1. **GUNICORN_TIMEOUT must be > LLM_TIMEOUT + 30s** (at minimum 30s buffer for network overhead).
2. **Recommended**: `LLM_TIMEOUT=180` (from `llmsetting.json`), `GUNICORN_TIMEOUT=240` (from `service.sh` default).
3. Slow/transient LLM responses should result in `manual_review` or `dep=false`, NOT HTTP 500.
4. If you need to change `llmsetting.json` timeout, increase `GUNICORN_TIMEOUT` accordingly: `GUNICORN_TIMEOUT=$((LLM_TIMEOUT + 60))`.

### Impact
Before RC4: intermittent HTTP 500 on slow LLM requests (observed `sw-mstp-001`, `rtr-ipsec-001` at 121s+).
After RC4: gunicorn allows up to 240s before worker restart; LLM timeout (180s) fires first for stalled requests.

### Long-term
Use async workers (gevent/uvicorn) or a job queue so slow LLM requests don't block the HTTP worker pool.

## Backlog Category Definitions

The `live_failure_backlog.py` tool uses these categories:

| Category | Meaning |
|----------|---------|
| `llm_quality_issue` | LLM produced insufficient/wrong output; validator correctly blocked |
| `annotation_issue` | Annotation expectations outdated/incorrect (system passes on clean path) |
| `validator_false_negative` | Validator missed an issue (uncommon; usually `llm_quality_issue` instead) |
| `validator_false_positive` | Validator incorrectly blocked correct output |
| `infra_issue` | Infrastructure problem (timeout, HTTP 500, etc.) |
| `unknown` | Cannot classify; needs manual triage |
