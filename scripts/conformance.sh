#!/usr/bin/env bash
# Run the conformance matrix: five cases for every capability Siphon claims.
#
# WHAT THIS IS FOR
#
# `cargo test` tells you the code does what the code was written to do. This
# asks a different question: for each format and detection we advertise, does
# the scanner find a planted value in the obvious place, in a hidden place,
# through a format-specific bypass — and, when the file is damaged, does it
# SAY so rather than quietly report clean? That last one is the reason this
# exists. A reader that returns Ok("") for a file it could not parse makes
# every caller downstream report "no findings" for content nobody read.
#
# Run it before pushing anything that touches an extractor, the normalizer or
# a pattern. It is fast — the fixtures are built in memory — so there is no
# reason to skip it.
#
# Usage:
#   scripts/conformance.sh                 # run everything
#   scripts/conformance.sh --capability docx
#   scripts/conformance.sh --json          # machine-readable
#   scripts/conformance.sh --list          # what would run
#   scripts/conformance.sh --test          # via cargo test, one test per format
#
# Exit status is 0 only when nothing failed unexpectedly and nothing Siphon
# advertises is unaccounted for. A *documented* gap — a case wrapped in
# `gap()` with a reason — is reported but does not fail the run; a documented
# gap that has started passing is reported too, so the entry gets removed
# instead of outliving the bug it described.

set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# The matrix lives behind its own feature so its fixture builders — a PDF
# writer, a PNG encoder — stay out of the shipped binary.
FEATURES="conformance"

if [ "${1:-}" = "--test" ]; then
    shift
    exec cargo test --features "${FEATURES}" --test conformance "$@"
fi

exec cargo run --quiet --features "${FEATURES}" --bin siphon-conformance -- "$@"
