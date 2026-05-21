# Known Limitations

## NAT Translation Flakiness

### Problem
Cisco ASA ↔ Huawei VRP NAT translations are non-deterministic due to LLM output quality variance:

| Case | Direction | Clean deployable rate | Notes |
|------|-----------|----------------------|-------|
| fw-nat-001 | Huawei→Cisco ASA | ≈60% | LLM may omit `nat (inside,outside)` or produce `security-policy` residue. Validator correctly blocks bad output. |
| fw-nat-server-001 | Cisco ASA→Huawei | ≈40% | LLM may use `ip address-set` instead of `nat server`, or output `Cisco` commands as residue. 100% `manual_review_required` expected. |

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
When the LLM API HTTPS connection stalls (TCP/SSL layer hang), the gunicorn worker may exceed the 120s timeout, causing HTTP 500. The LLM timeout is 45s but socket-level stalls may not trigger Python's `urlopen()` timeout.

### Impact
Intermittent live bench failures (observed with `rtr-ipsec-001`). Not reproducible on every run — depends on LLM API responsiveness.

### Mitigation
- Increase gunicorn `--timeout` from 120s to 240s for production.
- Ensure LLM client uses `requests.post` (which handles timeouts more reliably) instead of `urllib`.
- Set `LLM_TIMEOUT` environment variable to a reasonable value (default 45s).

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
