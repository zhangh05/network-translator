#!/bin/bash
# Phase 8C: Audit Traceability Drill
# Runs 2 integration chains and produces auditable evidence record.
#
# Usage:
#   PYTHONPATH=. bash scripts/audit_trace.sh [--json]
#
# Output:
#   docs/audit/trace_{run_id}.json  — machine-readable audit record
#   stdout                          — human-readable summary

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

RUN_ID="trace-$(date +%Y%m%d-%H%M%S)"
TIMESTAMP="$(date -Iseconds)"
COMMIT_HASH="$(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
SCHEMA_VERSION="1.0"

PYTHON="${PYTHON:-venv/bin/python3}"
JSON_FLAG="${1:-}"

echo "============================================"
echo "  Audit Traceability Drill"
echo "============================================"
echo "  Run ID:      $RUN_ID"
echo "  Timestamp:   $TIMESTAMP"
echo "  Commit:      $COMMIT_HASH"
echo "  Schema:      $SCHEMA_VERSION"
echo "============================================"
echo ""

# ── Chain 1: H3C → Cisco SWITCH (Phase 6 integration) ─────────────────
echo "--- Chain 1: H3C → Cisco SWITCH (phase6) ---"
CHAIN1_START=$(date +%s%N)
C1_OUTPUT=$(PYTHONPATH=. $PYTHON -m pytest tests/test_integration_phase6.py -v --tb=short 2>&1 || true)
CHAIN1_END=$(date +%s%N)
CHAIN1_MS=$(( (CHAIN1_END - CHAIN1_START) / 1000000 ))

C1_PASSED=$(echo "$C1_OUTPUT" | grep -c "PASSED" || true)
C1_FAILED=$(echo "$C1_OUTPUT" | grep -c "FAILED" || true)
C1_TOTAL=$((C1_PASSED + C1_FAILED))

echo "  Tests: ${C1_PASSED} passed, ${C1_FAILED} failed, ${C1_TOTAL} total"
echo "  Time:  ${CHAIN1_MS}ms"
echo ""

# ── Chain 2: ROUTER OSPF mismatch (Phase 7 integration) ────────────────
echo "--- Chain 2: ROUTER OSPF (phase7 deep + mismatch) ---"
CHAIN2_START=$(date +%s%N)
C2_OUTPUT=$(PYTHONPATH=. $PYTHON -m pytest tests/test_integration_phase7.py -v --tb=short 2>&1 || true)
CHAIN2_END=$(date +%s%N)
CHAIN2_MS=$(( (CHAIN2_END - CHAIN2_START) / 1000000 ))

C2_PASSED=$(echo "$C2_OUTPUT" | grep -c "PASSED" || true)
C2_FAILED=$(echo "$C2_OUTPUT" | grep -c "FAILED" || true)
C2_TOTAL=$((C2_PASSED + C2_FAILED))

echo "  Tests: ${C2_PASSED} passed, ${C2_FAILED} failed, ${C2_TOTAL} total"
echo "  Time:  ${CHAIN2_MS}ms"
echo ""

# ── Build JSON record ──────────────────────────────────────────────────
C1_RESULT="PASS"
[ "$C1_FAILED" -gt 0 ] && C1_RESULT="FAIL"
C2_RESULT="PASS"
[ "$C2_FAILED" -gt 0 ] && C2_RESULT="FAIL"

AUDIT_RECORD='{
  "schema_version": "'"$SCHEMA_VERSION"'",
  "generated_at": "'"$TIMESTAMP"'",
  "commit_hash": "'"$COMMIT_HASH"'",
  "run_id": "'"$RUN_ID"'",
  "phase": "8C",
  "drill": "minimum-traceability",
  "chains": [
    {
      "name": "H3C→Cisco SWITCH",
      "test_file": "tests/test_integration_phase6.py",
      "result": "'"$C1_RESULT"'",
      "passed": '"$C1_PASSED"',
      "failed": '"$C1_FAILED"',
      "total": '"$C1_TOTAL"',
      "timing_ms": '"$CHAIN1_MS"'
    },
    {
      "name": "ROUTER OSPF (deep + mismatch)",
      "test_file": "tests/test_integration_phase7.py",
      "result": "'"$C2_RESULT"'",
      "passed": '"$C2_PASSED"',
      "failed": '"$C2_FAILED"',
      "total": '"$C2_TOTAL"',
      "timing_ms": '"$CHAIN2_MS"'
    }
  ],
  "summary": {
    "total_chains": 2,
    "chains_passed": '"$(( (C1_FAILED==0) + (C2_FAILED==0) ))"',
    "chains_failed": '"$(( (C1_FAILED>0) + (C2_FAILED>0) ))"'
  }
}'

# ── Write output ───────────────────────────────────────────────────────
OUTPUT_FILE="docs/audit/${RUN_ID}.json"
echo "$AUDIT_RECORD" > "$OUTPUT_FILE"
echo "Audit record written to $OUTPUT_FILE"
echo ""

# ── Summary ────────────────────────────────────────────────────────────
echo "============================================"
echo "  Drill Summary"
echo "============================================"
echo "  Schema:      $SCHEMA_VERSION"
echo "  Run ID:      $RUN_ID"
echo "  Commit:      $COMMIT_HASH"
echo "  Generated:   $TIMESTAMP"
echo "  Chain 1:     $C1_RESULT ($C1_PASSED/$C1_TOTAL passed)"
echo "  Chain 2:     $C2_RESULT ($C2_PASSED/$C2_TOTAL passed)"
echo "============================================"

# Exit non-zero if any chain failed
if [ "$C1_FAILED" -gt 0 ] || [ "$C2_FAILED" -gt 0 ]; then
    echo "WARNING: Some chains have failures. Review audit record."
    exit 1
fi

echo "All chains passed. Audit OK."
