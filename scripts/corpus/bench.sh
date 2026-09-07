#!/usr/bin/env bash
# scripts/corpus/bench.sh — real-document throughput benchmark.
#
# Scans each file in corpus/raw/ with the siphon CLI, measures wall-clock
# time per file, then prints a throughput summary. Results are appended to
# corpus/bench.log for trend tracking.
#
# This complements the synthetic benchmark (cargo run --release --bin
# benchmark), which scans repeated template strings. Real documents differ
# in ways that matter: varying keyword density, normalization-triggering
# characters, and format diversity. Together they give a fuller picture of
# scanner performance.
#
# Requirements: siphon binary on PATH; python3 for JSON parsing
# Usage: bash scripts/corpus/bench.sh [--quiet]
#
# --quiet: suppress per-file output; print only the summary

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CORPUS_DIR="$REPO_ROOT/corpus/raw"
LOG_FILE="$REPO_ROOT/corpus/bench.log"
QUIET=0
for arg in "$@"; do [ "$arg" = "--quiet" ] && QUIET=1; done

if ! command -v siphon &>/dev/null; then
    echo "error: 'siphon' not found on PATH." >&2
    echo "       Build with: cargo build --release" >&2
    echo "       Then:       export PATH=\"\$PWD/target/release:\$PATH\"" >&2
    exit 1
fi

if [ ! -d "$CORPUS_DIR" ] || [ -z "$(ls -A "$CORPUS_DIR" 2>/dev/null)" ]; then
    echo "error: corpus/raw/ is empty. Run scripts/corpus/fetch.sh first." >&2
    exit 1
fi

SIPHON_VERSION=$(siphon info 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ "$QUIET" -eq 0 ]; then
    echo "Siphon corpus benchmark — $TIMESTAMP"
    echo "Version: $SIPHON_VERSION"
    echo "Corpus:  $CORPUS_DIR"
    echo ""
    printf "  %-52s  %9s  %9s  %8s\n" "File" "Size" "Time (ms)" "MB/s"
    printf "  %s\n" "$(printf '%.0s-' {1..86})"
fi

TOTAL_BYTES=0
TOTAL_MS=0
FILE_COUNT=0

# Collect and sort by size (smallest first)
declare -a FILES=()
while IFS= read -r -d '' f; do
    FILES+=("$f")
done < <(find "$CORPUS_DIR" -type f -print0 | sort -z)

# Sort by file size
declare -a SORTED_FILES=()
while IFS= read -r f; do
    SORTED_FILES+=("$f")
done < <(
    for f in "${FILES[@]}"; do
        size=$(wc -c < "$f")
        echo "$size $f"
    done | sort -n | awk '{print $2}'
)

for file in "${SORTED_FILES[@]}"; do
    fname="$(basename "$file")"
    size=$(wc -c < "$file")

    # Time the scan; capture output to /dev/null (we care about speed, not findings)
    start_ns=$(date +%s%N 2>/dev/null || python3 -c "import time; print(int(time.time()*1e9))")
    siphon scan "$file" --format json --min-confidence 0.5 > /dev/null 2>&1 || true
    end_ns=$(date +%s%N 2>/dev/null || python3 -c "import time; print(int(time.time()*1e9))")

    elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    if [ "$elapsed_ms" -le 0 ]; then elapsed_ms=1; fi

    mbps=$(awk "BEGIN {printf \"%.1f\", ($size / 1048576) / ($elapsed_ms / 1000.0)}")
    size_str=$(awk "BEGIN {
        s=$size
        if (s >= 1048576) printf \"%.1f MB\", s/1048576
        else if (s >= 1024) printf \"%.1f KB\", s/1024
        else printf \"%d B\", s
    }")

    TOTAL_BYTES=$((TOTAL_BYTES + size))
    TOTAL_MS=$((TOTAL_MS + elapsed_ms))
    FILE_COUNT=$((FILE_COUNT + 1))

    if [ "$QUIET" -eq 0 ]; then
        printf "  %-52s  %9s  %9s  %8s\n" \
            "${fname:0:52}" "$size_str" "${elapsed_ms}ms" "${mbps} MB/s"
    fi
done

if [ "$FILE_COUNT" -eq 0 ]; then
    echo "No files found in $CORPUS_DIR" >&2
    exit 1
fi

TOTAL_MB=$(awk "BEGIN {printf \"%.2f\", $TOTAL_BYTES / 1048576}")
TOTAL_S=$(awk "BEGIN {printf \"%.3f\", $TOTAL_MS / 1000.0}")
AGG_MBPS=$(awk "BEGIN {printf \"%.1f\", ($TOTAL_BYTES / 1048576) / ($TOTAL_MS / 1000.0)}")

if [ "$QUIET" -eq 0 ]; then
    printf "  %s\n" "$(printf '%.0s-' {1..86})"
    printf "  %-52s  %9s  %9s  %8s\n" \
        "TOTAL ($FILE_COUNT files)" "${TOTAL_MB} MB" "${TOTAL_S}s" "${AGG_MBPS} MB/s"
    echo ""
fi

echo "Corpus throughput: ${AGG_MBPS} MB/s  ($TOTAL_MB MB in ${TOTAL_S}s, $FILE_COUNT files)"

# Append structured record to bench.log
{
    echo "---"
    echo "timestamp: $TIMESTAMP"
    echo "siphon_version: $SIPHON_VERSION"
    echo "files: $FILE_COUNT"
    echo "total_mb: $TOTAL_MB"
    echo "total_s: $TOTAL_S"
    echo "throughput_mbps: $AGG_MBPS"
} >> "$LOG_FILE"

echo "Appended to: $LOG_FILE"
