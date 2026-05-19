# Corpus

Real-world network configuration samples for building and validating the translator.

## Directory Structure

```
corpus/
├── README.md              This file
├── schema.json            Annotation schema
├── samples/               Raw / pre-sanitized configs (gitignored — never committed)
├── sanitized/             Sanitized configs (safe to commit)
└── annotations/           JSON annotations per entry (safe to commit)
```

## Lifecycle

```
Real config collected
    ↓
corpus/samples/            → raw, gitignored, never shared
    ↓
tools/corpus_sanitize.py   → redact IPs, passwords, hostnames, keys
    ↓
corpus/sanitized/          → clean, safe to commit
    ↓
tools/corpus_validate.py   → validate annotation completeness
    ↓
corpus/annotations/        → structured metadata per entry
    ↓
tools/gen_bench_cases.py   → (future) generate bench cases from corpus
    ↓
bench/cases/               → permanent benchmark case
```

## Security

- **Never commit raw configs.** The `samples/` directory is in `.gitignore`.
- Run `corpus_sanitize.py` before moving any config to `sanitized/`.
- All sanitized files must pass `corpus_validate.py` before being committed.
- `original_hash` in annotations enables integrity verification without storing the raw file.

## Adding an Entry

1. Place the raw config in `samples/` (gitignored, safe)
2. Run `corpus_sanitize.py` to produce a sanitized version in `sanitized/`
3. Create a JSON annotation file in `annotations/` following `schema.json`
4. Run `corpus_validate.py` to check the annotation
5. Commit `sanitized/` and `annotations/` only
