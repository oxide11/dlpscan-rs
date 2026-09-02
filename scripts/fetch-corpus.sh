#!/usr/bin/env bash
#
# Fetch a large test corpus that is deliberately not stored in git.
#
# Corpora run to tens or hundreds of megabytes — the Canada contact corpus is
# ~49 MB and the US one is ~600 MB — so committing them would bloat every
# clone, permanently, for data that only the detection-quality suites read.
# What *is* committed is the part worth keeping in history: PROVENANCE.md, the
# source registry, the manifest and SHA256SUMS.txt. Those make a fetched copy
# verifiable, which is the point.
#
# Usage:
#   scripts/fetch-corpus.sh                     # fetch every known corpus
#   scripts/fetch-corpus.sh canada_contact_v1   # fetch one
#   scripts/fetch-corpus.sh --check             # report what is present
#
# Source is chosen by environment, in order:
#
#   SIPHON_CORPUS_DIR       a local directory to copy from (offline / CI cache)
#   SIPHON_CORPUS_BASE_URL  an HTTPS base URL; files are fetched as
#                           $BASE_URL/<corpus>/<filename>
#
# With neither set the script reports what is missing and exits 0, because a
# missing corpus is not an error: the suites that use it skip when it is
# absent so that a contributor without network access can still run everything
# else.
#
# Cloudflare R2 is the intended host — see PROVENANCE.md in each corpus
# directory for the bucket layout and why R2 over the alternatives.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS_ROOT="$REPO_ROOT/tests/corpus"

# Corpora that have external bulk files. A directory is listed here once its
# SHA256SUMS.txt references files that are not committed.
KNOWN_CORPORA=("canada_contact_v1")

check_only=false
targets=()
for arg in "$@"; do
  case "$arg" in
    --check) check_only=true ;;
    -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) targets+=("$arg") ;;
  esac
done
[[ ${#targets[@]} -eq 0 ]] && targets=("${KNOWN_CORPORA[@]}")

# Files listed in SHA256SUMS.txt but absent on disk are the ones to fetch.
missing_files() {
  local dir="$1"
  [[ -f "$dir/SHA256SUMS.txt" ]] || return 0
  while read -r _sum name; do
    name="${name#\*}"
    [[ -n "$name" && ! -f "$dir/$name" ]] && printf '%s\n' "$name"
  done < "$dir/SHA256SUMS.txt"
}

overall_missing=0

for corpus in "${targets[@]}"; do
  dir="$CORPUS_ROOT/$corpus"
  if [[ ! -d "$dir" ]]; then
    echo "unknown corpus: $corpus" >&2
    exit 2
  fi

  mapfile -t need < <(missing_files "$dir")

  # Nothing absent still means nothing verified. A file that is present but
  # corrupt is worse than one that is missing, because the suites would run
  # against it and measure the wrong thing silently — so verify before
  # declaring the corpus complete.
  if [[ ${#need[@]} -eq 0 ]]; then
    if ( cd "$dir" && sha256sum -c SHA256SUMS.txt --quiet ) 2>/dev/null; then
      echo "$corpus: complete and verified"
    else
      echo "$corpus: PRESENT BUT CORRUPT — checksums do not match" >&2
      ( cd "$dir" && sha256sum -c SHA256SUMS.txt 2>&1 | grep -v ': OK$' | sed 's/^/  /' ) >&2
      echo "  delete the offending files and re-run to refetch" >&2
      exit 1
    fi
    continue
  fi

  if $check_only; then
    echo "$corpus: ${#need[@]} file(s) missing — ${need[*]}"
    overall_missing=$(( overall_missing + ${#need[@]} ))
    continue
  fi

  if [[ -n "${SIPHON_CORPUS_DIR:-}" ]]; then
    echo "$corpus: copying ${#need[@]} file(s) from $SIPHON_CORPUS_DIR"
    for f in "${need[@]}"; do
      src="$SIPHON_CORPUS_DIR/$corpus/$f"
      [[ -f "$src" ]] || { echo "  missing at source: $src" >&2; exit 1; }
      cp "$src" "$dir/$f"
    done
  elif [[ -n "${SIPHON_CORPUS_BASE_URL:-}" ]]; then
    echo "$corpus: downloading ${#need[@]} file(s)"
    for f in "${need[@]}"; do
      url="${SIPHON_CORPUS_BASE_URL%/}/$corpus/$f"
      echo "  $f"
      # --fail so an HTML error page is never written over a data file.
      curl -sSfL --retry 3 --retry-delay 2 -o "$dir/$f" "$url"
    done
  else
    echo "$corpus: ${#need[@]} file(s) missing and no source configured."
    echo "  set SIPHON_CORPUS_DIR or SIPHON_CORPUS_BASE_URL; see PROVENANCE.md"
    overall_missing=$(( overall_missing + ${#need[@]} ))
    continue
  fi

  # Always verify. A corpus whose checksums do not match is worse than one
  # that is absent, because the suites would silently measure the wrong thing.
  echo "$corpus: verifying"
  ( cd "$dir" && sha256sum -c SHA256SUMS.txt --quiet ) || {
    echo "  CHECKSUM MISMATCH — refusing to leave a corrupt corpus in place" >&2
    for f in "${need[@]}"; do rm -f "$dir/$f"; done
    exit 1
  }
  echo "$corpus: complete and verified"
done

if $check_only && [[ $overall_missing -gt 0 ]]; then
  echo
  echo "$overall_missing file(s) missing. Suites that need them will skip."
fi
