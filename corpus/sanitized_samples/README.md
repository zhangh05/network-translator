# Sanitized Corpus Samples — Git-Tracked Evaluation Data

This directory contains **sanitized, git-tracked** multi-vendor network configuration
samples used to evaluate the fallback translator. Unlike `corpus/samples/` (which may
contain local/private raw configs and is `.gitignore`'d), this directory is versioned
and reproducible.

## Sample Policy

- **No real IPs**: Only RFC 1918 private addresses, documentation prefixes
  (203.0.113.0/24), or TEST-NET ranges (198.51.100.0/24, 192.0.2.0/24).
- **No real secrets**: All passwords, keys, SNMP community strings use
  `<redacted>` or obviously fake values.
- **No real hostnames**: Generic names like `SW-CORE-01`, `RTR-EDGE`, `FW-PROD`.
- **10–50 lines**: Each sample is a focused, realistic snippet.
- **Explicit metadata**: `manifest.json` documents required translations and
  manual review expectations.

## Directory distinction

| Path | Tracked | Purpose |
|------|---------|---------|
| `corpus/sanitized_samples/` | **Yes (git)** | CI-usable, reproducible evaluation corpus |
| `corpus/samples/` | **No (.gitignore)** | Local raw/private samples, not for CI |

## Evaluation Workflow

```
corpus/sanitized_samples/*.txt
    ──→  scripts/evaluate_corpus_fallback.py
        ──→  reports/corpus_fallback_eval.json
        ──→  reports/CORPUS_FALLBACK_EVAL.md
```

See `docs/FALLBACK_GAP_ANALYSIS.md` for the derived gap analysis.
