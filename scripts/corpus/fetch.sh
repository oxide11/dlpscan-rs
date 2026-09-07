#!/usr/bin/env bash
# scripts/corpus/fetch.sh — download the performance corpus.
#
# Fetches public-domain documents from Project Gutenberg, govinfo.gov, and
# federalregister.gov into corpus/raw/. All sources are in the US public
# domain. Run once to populate; re-running is idempotent (skips files that
# already exist).
#
# After fetching, run scripts/corpus/screen.sh to verify no real sensitive
# data is present before using the corpus for benchmarking.
#
# Requirements: curl, bash 4+
# Usage: bash scripts/corpus/fetch.sh [--force]
#
# --force: re-download even if the file already exists

set -euo pipefail

CORPUS_DIR="$(cd "$(dirname "$0")/../.." && pwd)/corpus/raw"
FORCE=0
for arg in "$@"; do [ "$arg" = "--force" ] && FORCE=1; done

mkdir -p "$CORPUS_DIR"
echo "Corpus directory: $CORPUS_DIR"
echo ""

TOTAL=0
SKIPPED=0
DOWNLOADED=0

download() {
    local label="$1"
    local url="$2"
    local dest="$CORPUS_DIR/$3"
    TOTAL=$((TOTAL + 1))
    if [ -f "$dest" ] && [ "$FORCE" -eq 0 ]; then
        local size
        size=$(wc -c < "$dest")
        echo "  skip  $label ($(numfmt --to=iec "$size" 2>/dev/null || echo "${size}B") already present)"
        SKIPPED=$((SKIPPED + 1))
        return
    fi
    echo "  fetch $label ..."
    if curl -fsSL --retry 3 --retry-delay 2 --max-time 60 -o "$dest" "$url"; then
        local size
        size=$(wc -c < "$dest")
        echo "        -> $(numfmt --to=iec "$size" 2>/dev/null || echo "${size}B")"
        DOWNLOADED=$((DOWNLOADED + 1))
    else
        echo "        !! FAILED (url: $url)" >&2
        rm -f "$dest"
    fi
}

# ---------------------------------------------------------------------------
# Project Gutenberg — plain text, UTF-8, public domain
# Cache URL format: https://www.gutenberg.org/cache/epub/{id}/pg{id}.txt
# ---------------------------------------------------------------------------
echo "=== Project Gutenberg (plain text) ==="

# --- Small tier: 50–200 KB ---
download "Metamorphosis — Kafka [~70 KB]" \
    "https://www.gutenberg.org/cache/epub/5200/pg5200.txt" \
    "gutenberg_5200_metamorphosis.txt"

download "Alice's Adventures in Wonderland — Carroll [~170 KB]" \
    "https://www.gutenberg.org/cache/epub/11/pg11.txt" \
    "gutenberg_11_alice.txt"

download "The Call of the Wild — London [~100 KB]" \
    "https://www.gutenberg.org/cache/epub/215/pg215.txt" \
    "gutenberg_215_call_of_the_wild.txt"

download "Peter Pan — Barrie [~110 KB]" \
    "https://www.gutenberg.org/cache/epub/16/pg16.txt" \
    "gutenberg_16_peter_pan.txt"

download "The Yellow Wallpaper — Gilman [~30 KB]" \
    "https://www.gutenberg.org/cache/epub/1952/pg1952.txt" \
    "gutenberg_1952_yellow_wallpaper.txt"

# --- Medium tier: 200–600 KB ---
download "The Wonderful Wizard of Oz — Baum [~230 KB]" \
    "https://www.gutenberg.org/cache/epub/55/pg55.txt" \
    "gutenberg_55_wizard_of_oz.txt"

download "The Picture of Dorian Gray — Wilde [~250 KB]" \
    "https://www.gutenberg.org/cache/epub/174/pg174.txt" \
    "gutenberg_174_dorian_gray.txt"

download "The Hound of the Baskervilles — Doyle [~210 KB]" \
    "https://www.gutenberg.org/cache/epub/2852/pg2852.txt" \
    "gutenberg_2852_hound_baskervilles.txt"

download "Frankenstein — Shelley [~430 KB]" \
    "https://www.gutenberg.org/cache/epub/84/pg84.txt" \
    "gutenberg_84_frankenstein.txt"

download "The Adventures of Tom Sawyer — Twain [~400 KB]" \
    "https://www.gutenberg.org/cache/epub/74/pg74.txt" \
    "gutenberg_74_tom_sawyer.txt"

download "The Scarlet Letter — Hawthorne [~440 KB]" \
    "https://www.gutenberg.org/cache/epub/25344/pg25344.txt" \
    "gutenberg_25344_scarlet_letter.txt"

download "Heart of Darkness — Conrad [~170 KB]" \
    "https://www.gutenberg.org/cache/epub/219/pg219.txt" \
    "gutenberg_219_heart_of_darkness.txt"

# --- Large tier: 600 KB – 1 MB ---
download "Adventures of Huckleberry Finn — Twain [~580 KB]" \
    "https://www.gutenberg.org/cache/epub/76/pg76.txt" \
    "gutenberg_76_huck_finn.txt"

download "The Adventures of Sherlock Holmes — Doyle [~580 KB]" \
    "https://www.gutenberg.org/cache/epub/1661/pg1661.txt" \
    "gutenberg_1661_sherlock_holmes.txt"

download "The Jungle — Sinclair [~500 KB]" \
    "https://www.gutenberg.org/cache/epub/140/pg140.txt" \
    "gutenberg_140_the_jungle.txt"

download "Pride and Prejudice — Austen [~700 KB]" \
    "https://www.gutenberg.org/cache/epub/1342/pg1342.txt" \
    "gutenberg_1342_pride_and_prejudice.txt"

download "A Tale of Two Cities — Dickens [~800 KB]" \
    "https://www.gutenberg.org/cache/epub/98/pg98.txt" \
    "gutenberg_98_tale_of_two_cities.txt"

download "Dracula — Stoker [~850 KB]" \
    "https://www.gutenberg.org/cache/epub/345/pg345.txt" \
    "gutenberg_345_dracula.txt"

download "War and Peace — Tolstoy Vol 1 [~900 KB]" \
    "https://www.gutenberg.org/cache/epub/2600/pg2600.txt" \
    "gutenberg_2600_war_and_peace.txt"

# ---------------------------------------------------------------------------
# govinfo.gov — US Congressional legislation, public domain
# These are HTML files; siphon's extractor reads their text content.
# ---------------------------------------------------------------------------
echo ""
echo "=== govinfo.gov (Congressional legislation, HTML) ==="

download "American Rescue Plan Act 2021 — HR1 enr [~750 KB]" \
    "https://www.govinfo.gov/content/pkg/BILLS-117hr1-enr/html/BILLS-117hr1-enr.htm" \
    "govinfo_BILLS-117hr1-enr.html"

download "Consolidated Appropriations Act 2021 — HR133 enr [large]" \
    "https://www.govinfo.gov/content/pkg/BILLS-116hr133-enr/html/BILLS-116hr133-enr.htm" \
    "govinfo_BILLS-116hr133-enr.html"

download "Inflation Reduction Act 2022 — HR5376 enr [~400 KB]" \
    "https://www.govinfo.gov/content/pkg/BILLS-117hr5376-enr/html/BILLS-117hr5376-enr.htm" \
    "govinfo_BILLS-117hr5376-enr.html"

# ---------------------------------------------------------------------------
# federalregister.gov — US Federal Register notices, public domain
# The full-text API returns plain text articles.
# ---------------------------------------------------------------------------
echo ""
echo "=== federalregister.gov (Federal Register notices, plain text) ==="

download "Federal Register — Cybersecurity EO 14028 full text [~120 KB]" \
    "https://www.federalregister.gov/documents/full_text/xml/2021/05/17/2021-10460.xml" \
    "fedreg_2021-10460_cyber_eo.xml"

download "Federal Register — HIPAA Omnibus Rule [~200 KB]" \
    "https://www.federalregister.gov/documents/full_text/xml/2013/01/25/2013-01073.xml" \
    "fedreg_2013-01073_hipaa_omnibus.xml"

download "Federal Register — GLBA Safeguards Rule [~150 KB]" \
    "https://www.federalregister.gov/documents/full_text/xml/2021/12/09/2021-25736.xml" \
    "fedreg_2021-25736_glba_safeguards.xml"

echo ""
echo "================================================================"
echo "Done. Total: $TOTAL  Downloaded: $DOWNLOADED  Skipped: $SKIPPED"
echo ""

# Count what we have
TOTAL_BYTES=0
FILE_COUNT=0
while IFS= read -r -d '' f; do
    size=$(wc -c < "$f")
    TOTAL_BYTES=$((TOTAL_BYTES + size))
    FILE_COUNT=$((FILE_COUNT + 1))
done < <(find "$CORPUS_DIR" -type f -print0 2>/dev/null)

if [ "$FILE_COUNT" -gt 0 ]; then
    TOTAL_MB=$(awk "BEGIN {printf \"%.1f\", $TOTAL_BYTES / 1048576}")
    echo "Corpus: $FILE_COUNT files, ${TOTAL_MB} MB total"
    echo ""
    echo "Next step: bash scripts/corpus/screen.sh"
fi
