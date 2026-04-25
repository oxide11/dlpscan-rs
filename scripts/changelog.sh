#!/usr/bin/env bash
# scripts/changelog.sh — generate a per-crate CHANGELOG block from
# Conventional-Commits history.
#
# Walks `git log <since>..HEAD`, filters to commits whose scope
# matches the target, and prints (or writes) markdown bullets in
# the per-crate Keep-a-Changelog format documented in CLAUDE.md.
#
# Pairs naturally with scripts/bump-version.sh: bump first (which
# inserts a `### <crate> X.Y.Z` heading + a TODO stub), then run
# changelog.sh to replace the stub with real bullets.
#
# Usage:
#   scripts/changelog.sh <target> [--since <ref>] [--write] [--include-internal]
#
#   <target>:  core | api | fs | launcher | cli | chart
#
#   --since <ref>      Walk commits since <ref> (a tag, branch, or
#                      SHA). Default: the most recent tag for the
#                      target (e.g. siphon-fs-v1.0.0); falls back
#                      to the workspace root commit if no tag.
#   --write            Replace the `_TODO: ..._` stub line under the
#                      most recent `### <crate> X.Y.Z` heading in
#                      CHANGELOG.md with the generated bullets. Without
#                      --write, prints to stdout for review.
#   --include-internal Keep chore/docs/ci/test/refactor commits.
#                      Default behaviour drops them — CHANGELOG.md
#                      is for user-visible entries per CLAUDE.md.
#
# Examples:
#   scripts/changelog.sh fs                 # since siphon-fs-v1.0.0
#   scripts/changelog.sh api --since main   # since main branch tip
#   scripts/changelog.sh fs --write         # populate the stub bullets

set -Eeuo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

SINCE=""
WRITE=false
INCLUDE_INTERNAL=false
TARGET=""

usage() { sed -n '1,32p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while (( $# > 0 )); do
    case "$1" in
        --since)            SINCE="$2"; shift ;;
        --since=*)          SINCE="${1#--since=}" ;;
        --write)            WRITE=true ;;
        --include-internal) INCLUDE_INTERNAL=true ;;
        -h|--help)          usage 0 ;;
        -*)                 echo "unknown flag: $1" >&2; usage 64 ;;
        *)
            if [[ -z "${TARGET}" ]]; then TARGET="$1"
            else echo "extra arg: $1" >&2; usage 64
            fi
            ;;
    esac
    shift
done

[[ -n "${TARGET}" ]] || usage 64

case "${TARGET}" in
    core|api|fs|launcher|cli|chart) ;;
    *) echo "unknown target: ${TARGET}" >&2; usage 64 ;;
esac

python3 - "${TARGET}" "${SINCE}" "${WRITE}" "${INCLUDE_INTERNAL}" <<'PY'
import os, re, subprocess, sys

target, since_arg, write_flag, include_internal_flag = sys.argv[1:5]
WRITE = write_flag == 'true'
INCLUDE_INTERNAL = include_internal_flag == 'true'

# Map a target to (a) its crate display name (for the markdown
# heading) and (b) the git tag prefix used to find the previous
# release boundary, and (c) the set of Conventional-Commits scopes
# that map onto this target. `chart` and `helm` are aliases — both
# mean the chart, just different conventions.
TARGETS = {
    'core':     {'crate': 'siphon-core',     'tag_prefix': 'siphon-core-v',     'scopes': {'core'}},
    'api':      {'crate': 'siphon-api',      'tag_prefix': 'siphon-api-v',      'scopes': {'api'}},
    'fs':       {'crate': 'siphon-fs',       'tag_prefix': 'siphon-fs-v',       'scopes': {'fs'}},
    'launcher': {'crate': 'siphon-launcher', 'tag_prefix': 'siphon-launcher-v', 'scopes': {'launcher'}},
    'cli':      {'crate': 'siphon',          'tag_prefix': 'siphon-cli-v',      'scopes': {'cli'}},
    'chart':    {'crate': 'helm-chart',      'tag_prefix': 'siphon-chart-v',    'scopes': {'chart', 'helm'}},
}
meta = TARGETS[target]

# Conventional-Commits types that are user-visible by default.
# Everything else needs --include-internal.
USER_VISIBLE = {'feat', 'fix', 'perf'}
INTERNAL     = {'chore', 'docs', 'refactor', 'test', 'ci', 'build', 'style', 'release'}

# ---- find the boundary --------------------------------------------------

def latest_tag(prefix):
    """Most recent tag matching <prefix>* by tag-side date. Empty
    string if none."""
    try:
        out = subprocess.check_output(
            ['git', 'tag', '--list', f'{prefix}*', '--sort=-v:refname'],
            text=True,
        )
    except subprocess.CalledProcessError:
        return ''
    for line in out.splitlines():
        line = line.strip()
        if line: return line
    return ''

if since_arg:
    since = since_arg
else:
    since = latest_tag(meta['tag_prefix'])
    if not since:
        # No tag yet for this crate — walk the whole history. The
        # changelog will be wide-mouthed but the user gets the
        # complete list to triage.
        since = ''

# ---- pull commits -------------------------------------------------------

def commits(since):
    rng = f'{since}..HEAD' if since else 'HEAD'
    out = subprocess.check_output(
        ['git', 'log', rng, '--no-merges', '--pretty=format:%H|%s'],
        text=True,
    )
    for line in out.splitlines():
        sha, _, subject = line.partition('|')
        yield sha, subject

# Conventional Commits subject:  <type>(<scope>)?(!)?: <subject>
HDR = re.compile(r'^([a-z]+)(?:\(([\w/-]+)\))?(!)?:\s*(.+)$')

# ---- filter + format ----------------------------------------------------

bullets = []
breaking_bullets = []
for sha, subject in commits(since):
    m = HDR.match(subject)
    if not m:
        # Non-conformant commit (e.g. a merge label, "Merge branch
        # X", a pre-Conventional-Commits commit). Skip silently
        # unless include-internal asked for everything.
        if INCLUDE_INTERNAL:
            bullets.append(f'- {subject}')
        continue
    ctype, scope, bang, body = m.group(1), m.group(2) or '', m.group(3) or '', m.group(4)
    is_breaking = bool(bang)
    is_internal = ctype in INTERNAL
    is_user     = ctype in USER_VISIBLE

    # Filter on scope. A commit lands in this target's section only
    # when its scope is on the target's accepted list.
    if scope and scope not in meta['scopes']:
        continue
    # No scope at all → only included if it's a top-level commit
    # for this target (rare; e.g. release commits on the cli).
    if not scope and target != 'cli':
        continue

    # Filter on type.
    if not (is_user or (INCLUDE_INTERNAL and (is_internal or ctype not in USER_VISIBLE | INTERNAL))):
        continue

    formatted = f'{ctype}: {body}' if not scope else f'{ctype}({scope}): {body}'
    line = f'- {formatted}'
    if is_breaking:
        breaking_bullets.append(f'- **BREAKING:** {formatted}')
    else:
        bullets.append(line)

# ---- emit ---------------------------------------------------------------

def render():
    chunks = []
    if breaking_bullets:
        chunks.append('\n'.join(breaking_bullets))
    if bullets:
        chunks.append('\n'.join(bullets))
    if not chunks:
        return '- _no qualifying commits_'
    return '\n'.join(chunks)

rendered = render()

if not WRITE:
    if since:
        sys.stderr.write(f'(commits since {since})\n')
    else:
        sys.stderr.write('(no prior tag for this target — full history)\n')
    print(rendered)
    sys.exit(0)

# --write: replace the stub line under the most recent
# `### <crate> X.Y.Z` heading in CHANGELOG.md with the generated
# bullets. We look for the exact stub bump-version.sh inserts:
#   - _TODO: replace this stub with the user-facing release notes._
path = 'CHANGELOG.md'
if not os.path.exists(path):
    raise SystemExit(f'{path} does not exist; run scripts/bump-version.sh first')

body = open(path).read()
# Find the most recent (== topmost) heading for this crate.
heading_re = re.compile(
    r'^### ' + re.escape(meta['crate']) + r' \d+\.\d+\.\d+\s*$',
    re.MULTILINE,
)
m = heading_re.search(body)
if not m:
    raise SystemExit(
        f'no `### {meta["crate"]} X.Y.Z` heading in CHANGELOG.md '
        f'— run `scripts/bump-version.sh {target} <bump>` first'
    )

# Find the bounded section: from this heading to the next ###/##/EOF.
section_start = m.end()
next_section = re.search(r'^(### |## )', body[section_start:], re.MULTILINE)
section_end = section_start + (next_section.start() if next_section else len(body) - section_start)

stub_re = re.compile(
    r'-\s*_TODO: replace this stub with the user-facing release notes\._',
)
section = body[section_start:section_end]
if not stub_re.search(section):
    raise SystemExit(
        'no TODO stub found under the heading — already populated? '
        'Edit CHANGELOG.md by hand to merge.'
    )

# Replace the entire stub line with the rendered bullets, and
# preserve a single trailing blank line before the next section.
new_section = stub_re.sub(rendered, section, count=1)
new_body = body[:section_start] + new_section + body[section_end:]
with open(path, 'w') as f: f.write(new_body)
print(f'  wrote   {path}')
print(f'  populated `### {meta["crate"]} ...` with {len(bullets) + len(breaking_bullets)} bullet(s)')
PY
