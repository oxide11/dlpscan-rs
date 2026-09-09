#!/usr/bin/env bash
# Push the per-crate release tag for every shipped artifact that does not have
# one yet.
#
# Tagging had been a manual step, and manual steps are the ones that get
# skipped: at the time this landed the remote carried ZERO tags while nine
# crates and the chart all had versions, and CHANGELOG.md described releases
# that no ref identified. "What shipped in siphon-fs 1.5.0" had no answer a
# tool could resolve. Four tags existed on someone's laptop and had never been
# pushed, which is the same as not existing.
#
#   scripts/release-tags.sh              # plan only — prints what it would do
#   scripts/release-tags.sh --push       # create and push the missing tags
#   scripts/release-tags.sh --remote up  # push somewhere other than origin
#
# Planning is the default and pushing is opt-in, because a tag is immutable by
# policy (CLAUDE.md, "Releases"): the cost of a wrong one is a ref that can
# never be corrected, only appended to.
#
# ── Which commit gets the tag ─────────────────────────────────────────────
#
# Not HEAD. A tag names the commit where that version was *introduced*, found
# by asking git which commit last changed that exact version string in that
# manifest. Tagging HEAD would be right for the wave that just merged and
# wrong for every older release still missing a tag — siphon-icap 0.3.0 has
# been at 0.3.0 for some time, and pointing its tag at today's commit would
# assert that everything merged since was part of it.
#
# This is what makes the first run a correct backfill rather than ten tags
# stacked on one commit.
#
# ── What it will not do ───────────────────────────────────────────────────
#
# It never moves or deletes a tag. An existing tag is left exactly as it is,
# even when it points somewhere this script would not have chosen, and the
# plan says so. Re-pointing a tag rewrites what a released artifact was.

set -euo pipefail

REMOTE="origin"
PUSH=0

while [ $# -gt 0 ]; do
    case "$1" in
        --push)   PUSH=1; shift ;;
        --remote) REMOTE="${2:?--remote needs a value}"; shift 2 ;;
        -h|--help)
            sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

cd "$(dirname "$0")/.."

green() { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
dim() { printf '\033[2m%s\033[0m\n' "$1"; }

# Every artifact that ships with a version of its own. The SBOM carries nine
# documents and the chart is versioned separately, so this is ten — CLAUDE.md's
# tag list named only six for a while, which is how siphon-icap, siphon-smtp,
# siphon-mail and siphon-auth went untagged without anyone noticing a rule had
# been broken.
#
#   <tag prefix>|<manifest>|<how to read the version>
ARTIFACTS="
siphon-cli|Cargo.toml|cargo
siphon-core|crates/siphon-core/Cargo.toml|cargo
siphon-api|crates/siphon-api/Cargo.toml|cargo
siphon-fs|crates/siphon-fs/Cargo.toml|cargo
siphon-icap|crates/siphon-icap/Cargo.toml|cargo
siphon-smtp|crates/siphon-smtp/Cargo.toml|cargo
siphon-launcher|crates/siphon-launcher/Cargo.toml|cargo
siphon-mail|crates/siphon-mail/Cargo.toml|cargo
siphon-auth|crates/siphon-auth/Cargo.toml|cargo
siphon-chart|deploy/helm/siphon/Chart.yaml|chart
"

# The [package] version, not a dependency's. Inter-crate deps in this
# workspace are `path =` only, but a future `version =` alongside one would
# otherwise be picked up here and tag the wrong number.
read_cargo_version() {
    sed -n '/^\[package\]/,/^\[[a-z]/p' "$1" | grep -m1 '^version' | sed 's/.*"\(.*\)".*/\1/'
}

read_chart_version() {
    grep -m1 '^version:' "$1" | sed 's/^version:[[:space:]]*//; s/["'"'"']//g'
}

# The commit that introduced this version string into this manifest. `-S`
# counts occurrences, so this is the commit that added the line rather than
# the last commit to touch the file for any reason.
introducing_commit() {
    local manifest="$1" needle="$2" sha
    sha=$(git log -1 --format=%H -S"$needle" -- "$manifest" 2>/dev/null || true)
    if [ -z "$sha" ]; then
        # No history for it — a version committed in the same breath as the
        # file's creation, or a shallow clone. HEAD is the honest fallback and
        # the plan labels it, because it is a guess where the others are not.
        echo "HEAD"
    else
        echo "$sha"
    fi
}

planned=0
skipped=0
mismatched=0
failed=0

# Tags the first pass deliberately refused to touch. The second pass MUST NOT
# push these: a tag flagged here points somewhere this script did not choose,
# and rescuing it would push the very ref the guard just protected. That bug
# was live for one commit — the guard printed "leaving both alone" and the
# rescue pass then queued the same tag.
CONFLICTING=" "

echo
echo "Release tags — ${REMOTE}"
echo

for line in $ARTIFACTS; do
    [ -n "$line" ] || continue
    prefix="${line%%|*}"
    rest="${line#*|}"
    manifest="${rest%%|*}"
    kind="${rest##*|}"

    if [ ! -f "$manifest" ]; then
        yellow "  ?  $prefix — $manifest not found, skipping"
        continue
    fi

    if [ "$kind" = "chart" ]; then
        version=$(read_chart_version "$manifest")
        needle="version: $version"
    else
        version=$(read_cargo_version "$manifest")
        needle="version = \"$version\""
    fi

    if [ -z "$version" ]; then
        yellow "  ?  $prefix — no version found in $manifest, skipping"
        continue
    fi

    tag="${prefix}-v${version}"

    # Remote is the authority. A tag present only locally is one that was
    # never pushed, which is exactly the state this script exists to fix.
    remote_sha=$(git ls-remote --tags "$REMOTE" "refs/tags/$tag" 2>/dev/null | awk '{print $1}' | head -1)

    if [ -n "$remote_sha" ]; then
        dim "  =  $tag already on $REMOTE"
        skipped=$((skipped + 1))
        continue
    fi

    target=$(introducing_commit "$manifest" "$needle")
    if [ "$target" = "HEAD" ]; then
        target=$(git rev-parse HEAD)
        note=" (fallback: no history for that version line)"
    else
        note=""
    fi
    short=$(git rev-parse --short "$target")
    subject=$(git log -1 --format=%s "$target" | cut -c1-58)

    # A local tag of the same name that points somewhere else is not something
    # to resolve silently. Report it and touch nothing: the local one may be
    # the true release and this script's guess the wrong one.
    local_sha=$(git rev-parse -q --verify "refs/tags/$tag^{commit}" 2>/dev/null || true)
    if [ -n "$local_sha" ] && [ "$local_sha" != "$(git rev-parse "$target^{commit}")" ]; then
        yellow "  !  $tag exists locally at $(git rev-parse --short "$local_sha"), not $short — leaving both alone"
        mismatched=$((mismatched + 1))
        CONFLICTING="${CONFLICTING}${tag} "
        continue
    fi

    if [ "$PUSH" -eq 1 ]; then
        if [ -z "$local_sha" ]; then
            git tag -a "$tag" "$target" -m "$prefix $version" >/dev/null
        fi
        if git push -q "$REMOTE" "refs/tags/$tag" 2>/dev/null; then
            green "  +  $tag -> $short  $subject$note"
            planned=$((planned + 1))
        else
            # The push is the step that fails when ref writes are denied, and
            # it fails per tag. Carry on so one refusal does not hide the
            # other nine, and exit non-zero at the end.
            yellow "  x  $tag -> $short  PUSH REFUSED"
            failed=$((failed + 1))
        fi
    else
        green "  +  $tag -> $short  $subject$note"
        planned=$((planned + 1))
    fi
done

# ── Second pass: local tags the remote has never seen ─────────────────────
#
# A tag created on a laptop and never pushed is not a release marker, it is a
# note to self that dies with the disk. Four of them were sitting in a
# container when this script was written — siphon-api-v2.5.0 and friends, all
# for versions long superseded, all pointing at real historical commits that
# nothing else recorded. They are not in the table above, because that table
# only knows about versions the tree currently carries.
rescued=0
for tag in $(git tag --list 'siphon-*-v*' 2>/dev/null); do
    git ls-remote --tags "$REMOTE" "refs/tags/$tag" 2>/dev/null | grep -q . && continue
    # Never rescue what the first pass refused. Without this the guard above
    # is decorative: it declines to re-point a tag, and then this loop pushes
    # that same tag to the commit the guard rejected.
    case "$CONFLICTING" in
        *" $tag "*)
            yellow "  x  $tag not rescued — first pass flagged it as conflicting"
            continue ;;
    esac
    sha=$(git rev-parse --short "$tag^{commit}" 2>/dev/null || echo "?")
    if [ "$PUSH" -eq 1 ]; then
        if git push -q "$REMOTE" "refs/tags/$tag" 2>/dev/null; then
            green "  ^  $tag -> $sha  (local-only tag, now pushed)"
            rescued=$((rescued + 1))
        else
            yellow "  x  $tag -> $sha  PUSH REFUSED"
            failed=$((failed + 1))
        fi
    else
        green "  ^  $tag -> $sha  (local-only tag, would be pushed)"
        rescued=$((rescued + 1))
    fi
done

echo
if [ "$PUSH" -eq 1 ]; then
    echo "pushed $planned, rescued $rescued local-only, already present $skipped, conflicting $mismatched, refused $failed"
else
    echo "would push $planned, rescue $rescued local-only, already present $skipped, conflicting $mismatched"
    dim "(plan only — re-run with --push to create them)"
fi

if [ "$failed" -gt 0 ]; then
    echo
    echo "Some tags could not be pushed. If this ran outside CI, the session's" >&2
    echo "egress policy may refuse ref writes — see CLAUDE.md, 'Releases'." >&2
    exit 1
fi

exit 0
