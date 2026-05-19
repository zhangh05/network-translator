#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-quick}"
echo "=== Iteration Check (mode=$MODE) ==="
echo ""

# 1. Corpus validate
echo "--- 1. corpus_validate ---"
PYTHONPATH=. python3 tools/corpus_validate.py 2>&1 | tail -3
echo ""

# 2. Corpus to bench
echo "--- 2. corpus_to_bench ---"
rm -rf bench/cases/corpus
PYTHONPATH=. python3 tools/corpus_to_bench.py 2>&1 | tail -2
echo ""

# 3. Static bench
echo "--- 3. static bench (corpus) ---"
PYTHONPATH=. python3 bench/run_cases.py --corpus-only --static-only 2>&1 | tail -8
echo ""

# 4. Pytest
echo "--- 4. pytest ---"
if [ "$MODE" = "quick" ]; then
    PYTHONPATH=. ./venv/bin/pytest tests/test_platform_validator.py tests/test_corpus_validate.py -q 2>&1 | tail -3 || true
else
    PYTHONPATH=. ./venv/bin/pytest tests/ -q 2>&1 | tail -3
fi
echo ""

# 5. Generate status report
echo "--- 5. status report ---"
mkdir -p reports
cat > reports/latest_status.md << STATUS
# Latest Status
Generated: $(date '+%Y-%m-%d %H:%M:%S')
Mode: $MODE

## Corpus Validate
$(PYTHONPATH=. python3 tools/corpus_validate.py 2>&1 | tail -3)

## Static Bench (Corpus)
$(PYTHONPATH=. python3 bench/run_cases.py --corpus-only --static-only 2>&1 | tail -5)

## Tests
$(if [ "$MODE" = "quick" ]; then PYTHONPATH=. ./venv/bin/pytest tests/test_platform_validator.py tests/test_corpus_validate.py -q 2>&1 | tail -3; else PYTHONPATH=. ./venv/bin/pytest tests/ -q 2>&1 | tail -3; fi)
STATUS
echo "Written: reports/latest_status.md"

echo ""
echo "=== Done ==="
