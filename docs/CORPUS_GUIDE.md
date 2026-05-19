# Corpus Guide

## What is the Corpus?

The corpus is a curated collection of real-world network configurations used to:

1. **Validate** — run live benchmarks against real configs
2. **Discover gaps** — find features/edge cases not covered by synthetic cases
3. **Evolve knowledge** — add knowledge `.md` files based on real failures
4. **Benchmark regression** — prevent regressions on real-world inputs

## Lifecycle

```
Collect → Sanitize → Annotate → Validate → Bench → Learn
```

### 1. Collect

Gather real network configurations from:

- Internal lab topologies
- Customer samples (with permission)
- Public documentation / vendor guides
- Community sources

**Raw configs go in `corpus/samples/`** which is gitignored. Never commit raw configs.

### 2. Sanitize

```bash
# Single file
python3 tools/corpus_sanitize.py corpus/samples/raw.txt > corpus/sanitized/entry.txt

# Directory batch
python3 tools/corpus_sanitize.py corpus/samples/ --out-dir corpus/sanitized/
```

The sanitizer redacts:
- IP addresses → `198.18.x.x` (RFC 5735 documentation range)
- Passwords, secrets, keys → `[REDACTED]`
- SNMP community strings → `[REDACTED]`
- Hostnames → `CORPUS-REDACTED`
- AS numbers → private range (64512–65535)
- Usernames → `[REDACTED]`

### 3. Annotate

Create a JSON annotation file following `corpus/schema.json`. Each annotation captures:

| Field | Required | Purpose |
|-------|----------|---------|
| `id` | yes | Unique entry identifier |
| `classification.vendor` | yes | Source vendor |
| `classification.features` | yes | Features present in the config |
| `classification.risk` | yes | Translation risk (high/medium/low) |
| `config.sanitized_path` | yes | Links to sanitized file |
| `annotation.expected_translation.key_lines` | yes | Lines that must appear in output |
| `annotation.expected_translation.must_not_contain` | yes | Source-vendor patterns banned from output |

### 4. Validate

```bash
# Full corpus validation
python3 tools/corpus_validate.py

# Single entry
python3 tools/corpus_validate.py --entry fw-nat-001

# Strict mode (verify hashes)
python3 tools/corpus_validate.py --strict
```

The validator checks:
- All required schema fields present
- All annotated files have matching sanitized configs
- Sanitized configs contain no raw IPs or secrets
- Line counts match between annotation and file
- Status/risk/vendor values are valid

### 5. Bench

Promote a corpus entry to a benchmark case:

1. Create a `bench/cases/` JSON case using the sanitized config
2. Set `target_vendor` and expected output patterns
3. Run: `python3 bench/run_cases.py --static`
4. If live: `python3 bench/run_cases.py --live --tier full`
5. Update annotation `benchmark.case_generated = true`

### 6. Learn

When a corpus entry fails translation:

1. Identify the root cause:
   - Missing knowledge? → Add `.md` to `knowledge_data/`
   - Missing analyzer? → Implement or extend analyzer
   - Validator false positive? → Tune validator
   - LLM mistake? → Improve prompt / add constraint
2. Fix the issue
3. Re-run bench: `python3 bench/run_cases.py --static --tier full`
4. Update annotation `annotation.verification`

## Corpus Structure

```
corpus/
├── README.md          This guide
├── schema.json        Annotation schema (JSON)
├── samples/           Raw configs — gitignored, never committed
├── sanitized/         Sanitized configs — safe to commit
│   ├── fw-nat-001.txt
│   ├── fw-nat-001.txt.annotation.json
│   ├── rtr-ospf-001.txt
│   ├── rtr-ospf-001.txt.annotation.json
│   └── ...
└── annotations/       Annotation files (may also be in sanitized/ as .annotation.json)
```

## Adding a New Entry (Quick Reference)

```bash
# 1. Place raw config
cp my-config.txt corpus/samples/

# 2. Sanitize
python3 tools/corpus_sanitize.py corpus/samples/my-config.txt > corpus/sanitized/my-config.txt

# 3. Create annotation
#    (copy and edit an existing one, or create from scratch per schema.json)
cp corpus/sanitized/fw-nat-001.txt.annotation.json corpus/sanitized/my-config.txt.annotation.json

# 4. Validate
python3 tools/corpus_validate.py

# 5. Commit (sanitized + annotation only)
git add corpus/sanitized/my-config.txt corpus/sanitized/my-config.txt.annotation.json
```

## Bench Migration

To generate a bench case from a corpus entry:

```bash
# Manual: create bench/cases/{domain}/{entry-id}.json with:
#   - "input": corpus/sanitized/{file}
#   - "expected": from annotation.expected_translation
#   - "risk": from classification.risk → tier: low→smoke, medium→core, high→full
```

This is a manual step currently. A `tools/corpus_to_bench.py` generator is planned.

## Quality Standards

| Check | Required |
|-------|----------|
| Sanitized file has no raw IPs | Yes |
| Sanitized file has no secrets | Yes |
| Annotation has all required fields | Yes |
| Annotation ID matches file name | Yes |
| Sanitized file exists for annotation | Yes |
| Features match registry.yaml names | Strongly recommended |
| bench case generated | Preferred for high-risk entries |
