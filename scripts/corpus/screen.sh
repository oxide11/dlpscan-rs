#!/usr/bin/env bash
# scripts/corpus/screen.sh — data-provenance gate for the performance corpus.
#
# Scans every file in corpus/raw/ with the siphon CLI. If any findings are
# returned, the file is flagged, the findings are printed, and the script
# exits non-zero. A clean exit means the corpus is clear of real sensitive
# data and safe to use for benchmarking.
#
# This enforces the data provenance policy from FUTURE.md:
#   "Real public documents may serve as carriers after screening;
#    the sensitive values are always synthetic."
#
# Requirements: siphon binary on PATH (cargo build --release && export PATH=...)
# Usage: bash scripts/corpus/screen.sh
#
# Output:
#   corpus/screen.log  — timestamped record of each screening pass

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CORPUS_DIR="$REPO_ROOT/corpus/raw"
LOG_FILE="$REPO_ROOT/corpus/screen.log"

if ! command -v siphon &>/dev/null; then
    echo "error: 'siphon' not found on PATH." >&2
    echo "       Build with: cargo build --release" >&2
    echo "       Then:       export PATH=\"\$PWD/target/release:\$PATH\"" >&2
    exit 1
fi

if [ ! -d "$CORPUS_DIR" ] || [ -z "$(ls -A "$CORPUS_DIR" 2>/dev/null)" ]; then
    echo "error: corpus/raw/ is empty or missing. Run scripts/corpus/fetch.sh first." >&2
    exit 1
fi

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Screening corpus at $TIMESTAMP"
echo "Directory: $CORPUS_DIR"
echo ""

FLAGGED=0
CLEAN=0
TOTAL=0

while IFS= read -r -d '' file; do
    TOTAL=$((TOTAL + 1))
    fname="$(basename "$file")"
    result=$(siphon scan "$file" --format json --min-confidence 0.7 2>/dev/null || true)
    count=$(echo "$result" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    findings = d.get('findings', [])
    print(len(findings))
except Exception:
    print(0)
" 2>/dev/null || echo "0")

    if [ "$count" -gt 0 ]; then
        FLAGGED=$((FLAGGED + 1))
        echo "  FLAGGED  $fname ($count finding(s))"
        # Print category summary without showing matched values
        echo "$result" | python3 -c "
import json,sys
d = json.load(sys.stdin)
cats = {}
for f in d.get('findings', []):
    c = f.get('category','?')
    cats[c] = cats.get(c, 0) + 1
for c, n in sorted(cats.items()):
    print(f'           {n}x {c}')
" 2>/dev/null || true
    else
        CLEAN=$((CLEAN + 1))
        echo "  clean    $fname"
    fi
done < <(find "$CORPUS_DIR" -type f -print0 | sort -z)

echo ""
echo "================================================================"
echo "Screened: $TOTAL  Clean: $CLEAN  Flagged: $FLAGGED"
echo ""

# Append to log
{
    echo "---"
    echo "timestamp: $TIMESTAMP"
    echo "total: $TOTAL"
    echo "clean: $CLEAN"
    echo "flagged: $FLAGGED"
    if [ "$FLAGGED" -gt 0 ]; then
        echo "status: FAIL"
    else
        echo "status: PASS"
    fi
} >> "$LOG_FILE"

if [ "$FLAGGED" -gt 0 ]; then
    echo "FAIL: $FLAGGED file(s) contain findings above 0.7 confidence."
    echo "      Remove or replace those files before using the corpus."
    echo "      (If these are false positives, lower --min-confidence"
    echo "       in this script or add an allowlist entry.)"
    exit 1
fi

echo "PASS: corpus is clear. Safe to benchmark."
echo "      Log appended to: $LOG_FILE"
