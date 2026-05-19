#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Network Translator — Project Status ==="
echo ""

# Git
echo "--- Git ---"
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "no tag")
DIRTY=$(git status --porcelain 2>/dev/null | wc -l)
echo "Branch: $BRANCH"
echo "Tag:    $TAG"
echo "Dirty:  $DIRTY files"

# Version
echo ""
echo "--- Version ---"
VERSION=$(cat VERSION 2>/dev/null || echo "no VERSION file")
echo "Version: $VERSION"

# Service health
echo ""
echo "--- Service ---"
HEALTHZ=$(curl -s --noproxy '*' --connect-timeout 3 http://127.0.0.1:5008/healthz 2>/dev/null || echo "unreachable")
echo "API health: $HEALTHZ"

# Pytest (last result cache)
echo ""
echo "--- Tests ---"
PYTEST_LOG=$(ls -t .pytest_cache/v/cache/lastfailed 2>/dev/null | head -1)
if [ -n "$PYTEST_LOG" ]; then
    # Run quick count
    python3 -c "
import subprocess, sys
r = subprocess.run([sys.executable, '-m', 'pytest', 'tests/', '-q', '--tb=no'], capture_output=True, text=True, timeout=60)
lines = r.stdout.strip().split('\n')
print(lines[-1] if lines else 'no output')
" 2>/dev/null || echo "pytest: run with 'scripts/project_status.sh --full'"
else
    echo "pytest: run 'scripts/project_status.sh --full' to execute"
fi

# Corpus validate
echo ""
echo "--- Corpus ---"
python3 -c "
import subprocess, sys
r = subprocess.run([sys.executable, 'tools/corpus_validate.py'], capture_output=True, text=True, timeout=15)
lines = r.stdout.strip().split('\n')
for l in lines:
    if 'errors' in l or 'warnings' in l or 'VALIDATION' in l:
        print(l)
" 2>/dev/null || echo "corpus_validate: not available"

# Static bench
echo ""
echo "--- Static Bench ---"
python3 -c "
import subprocess, sys
r = subprocess.run([sys.executable, 'bench/run_cases.py', '--corpus-only', '--static-only'], capture_output=True, text=True, timeout=20)
lines = r.stdout.strip().split('\n')
for l in lines:
    if 'Static:' in l or 'Live:' in l or 'static' in l:
        print(l)
" 2>/dev/null || echo "static bench: not available"

# Backlog
echo ""
echo "--- Backlog ---"
if [ -f reports/live_failure_backlog.md ]; then
    P0=$(grep -c 'P0' reports/live_failure_backlog.md 2>/dev/null || echo 0)
    P1=$(grep -c 'P1' reports/live_failure_backlog.md 2>/dev/null || echo 0)
    echo "Backlog entries: P0=$P0 P1=$P1 total=$(wc -l < reports/live_failure_backlog.md 2>/dev/null)"
else
    echo "No backlog file"
fi

echo ""
echo "=== Done ==="
