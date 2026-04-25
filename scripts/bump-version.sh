#!/usr/bin/env bash
# scripts/bump-version.sh — bump a crate's version everywhere it lives.
#
# Implements the lockstep checklist documented in CLAUDE.md
# ("Lockstep updates within one crate"). One command, one crate;
# touches the Cargo manifest, the matching Dockerfile LABEL, the
# Helm `values.yaml` image tag, the dev `docker-compose.yml` image
# pin, and adds a stub entry to CHANGELOG.md. Runs `cargo check`
# afterwards so `Cargo.lock` picks up the new resolved version
# without a separate step.
#
# Usage:
#   scripts/bump-version.sh <target> <bump>
#
#   <target>:  core | api | fs | launcher | cli | chart
#   <bump>:    patch | minor | major | X.Y.Z   (explicit version)
#
# Examples:
#   scripts/bump-version.sh fs patch         # 1.0.0 -> 1.0.1
#   scripts/bump-version.sh api minor        # 2.1.0 -> 2.2.0
#   scripts/bump-version.sh core major       # 2.1.0 -> 3.0.0 (warns on cascade)
#   scripts/bump-version.sh chart 2.1.0      # explicit version
#
# Flags:
#   --dry-run        Print what would change, don't write.
#   --no-changelog   Skip the CHANGELOG.md stub. Useful when the
#                    real entry is being authored by hand in the
#                    same commit.
#   --force          Allow a non-forward bump (e.g. 2.1.0 -> 1.0.0
#                    for the deliberate per-crate renumbering).
#
# Notes:
#   * `core` has no Dockerfile / Helm tag / compose entry of its
#     own; bumping it only touches the Cargo manifest. A MAJOR
#     bump prints a cascade warning naming the downstream crates
#     that need their own bumps in the same release wave per
#     CLAUDE.md "core MAJOR cascades".
#   * `chart` only moves `Chart.yaml` `version:`. The `appVersion:`
#     label is left alone — the operator sets it manually to
#     whichever crate version is the headline of the release wave.

set -Eeuo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

DRY_RUN=false
NO_CHANGELOG=false
FORCE=false
TARGET=""
BUMP=""

usage() {
    sed -n '1,40p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while (( $# > 0 )); do
    case "$1" in
        --dry-run)      DRY_RUN=true ;;
        --no-changelog) NO_CHANGELOG=true ;;
        --force)        FORCE=true ;;
        -h|--help)      usage 0 ;;
        -*)             echo "unknown flag: $1" >&2; usage 64 ;;
        *)
            if   [[ -z "${TARGET}" ]]; then TARGET="$1"
            elif [[ -z "${BUMP}"   ]]; then BUMP="$1"
            else echo "extra arg: $1" >&2; usage 64
            fi
            ;;
    esac
    shift
done

[[ -n "${TARGET}" && -n "${BUMP}" ]] || usage 64

case "${TARGET}" in
    core|api|fs|launcher|cli|chart) ;;
    *) echo "unknown target: ${TARGET}" >&2; usage 64 ;;
esac

# All file mutations + version arithmetic live in Python — the
# regex anchors are tighter, the YAML edits are structural, and the
# CHANGELOG insert needs proper line splicing. Bash drives the flow;
# Python does the writes.
python3 - "${TARGET}" "${BUMP}" "${DRY_RUN}" "${NO_CHANGELOG}" "${FORCE}" <<'PY'
import datetime as _dt
import os, re, subprocess, sys

target, bump, dry_run, no_changelog, force = sys.argv[1:6]
DRY_RUN      = dry_run == 'true'
NO_CHANGELOG = no_changelog == 'true'
FORCE        = force == 'true'

# ---- target metadata ----------------------------------------------------

TARGETS = {
    'core': {
        'crate':   'siphon-core',
        'cargo':   'crates/siphon-core/Cargo.toml',
    },
    'api': {
        'crate':       'siphon-api',
        'cargo':       'crates/siphon-api/Cargo.toml',
        'dockerfile':  'deploy/Dockerfile.api',
        'values_path': 'api.image.tag',
        'compose_img': 'siphon-api',
    },
    'fs': {
        'crate':       'siphon-fs',
        'cargo':       'crates/siphon-fs/Cargo.toml',
        'dockerfile':  'deploy/Dockerfile.fs',
        'values_path': 'fs.image.tag',
        'compose_img': 'siphon-fs',
    },
    'launcher': {
        'crate':   'siphon-launcher',
        'cargo':   'crates/siphon-launcher/Cargo.toml',
    },
    'cli': {
        'crate':   'siphon',
        'cargo':   'Cargo.toml',
    },
    'chart': {
        'crate':       None,
        'chart_yaml':  'deploy/helm/siphon/Chart.yaml',
    },
}

meta = TARGETS[target]

# ---- helpers ------------------------------------------------------------

def banner(msg): print(f'▶ {msg}')
def warn(msg):   print(f'⚠ {msg}', file=sys.stderr)
def read(path):
    with open(path) as f: return f.read()
def write(path, body):
    if DRY_RUN:
        print(f'  [dry-run] would write {path}')
        return
    with open(path, 'w') as f: f.write(body)
    print(f'  wrote   {path}')

def parse_semver(s):
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)$', s.strip())
    if not m: raise SystemExit(f'not a SemVer: {s!r}')
    return tuple(int(x) for x in m.groups())

def fmt_semver(t): return f'{t[0]}.{t[1]}.{t[2]}'

def compute_new(current, bump):
    if re.match(r'^\d+\.\d+\.\d+$', bump):
        return bump
    cur = parse_semver(current)
    if   bump == 'patch': return fmt_semver((cur[0], cur[1], cur[2] + 1))
    elif bump == 'minor': return fmt_semver((cur[0], cur[1] + 1, 0))
    elif bump == 'major': return fmt_semver((cur[0] + 1, 0, 0))
    raise SystemExit(f'unknown bump: {bump!r}')

# ---- read current version -----------------------------------------------

def read_cargo_version(path):
    body = read(path)
    # Anchor strictly on `[package]` section + first `version =` after
    # it. A naive regex would pick up a `[dependencies]` entry that
    # has the same crate name with a `version = "..."` constraint.
    m = re.search(
        r'\[package\][^\[]*?\nversion\s*=\s*"(\d+\.\d+\.\d+)"',
        body, re.DOTALL,
    )
    if not m: raise SystemExit(f'no [package].version in {path}')
    return m.group(1)

def read_chart_version(path):
    body = read(path)
    m = re.search(r'^version:\s*([\d.]+)\s*$', body, re.MULTILINE)
    if not m: raise SystemExit(f'no version: in {path}')
    return m.group(1)

if target == 'chart':
    current = read_chart_version(meta['chart_yaml'])
else:
    current = read_cargo_version(meta['cargo'])

new = compute_new(current, bump)

if current == new:
    banner(f'{target}: already at {current} — nothing to do')
    sys.exit(0)

# Refuse to downgrade unless --force. The deliberate per-crate
# renumbering (e.g. siphon-fs 2.1.0 -> 1.0.0) goes through --force.
cur_t, new_t = parse_semver(current), parse_semver(new)
if new_t < cur_t and not FORCE:
    raise SystemExit(
        f'refusing to bump {target} backwards ({current} -> {new}); '
        f'pass --force if this is a deliberate renumbering'
    )

banner(f'{target}: {current} → {new}{" [dry-run]" if DRY_RUN else ""}')

# ---- file mutations -----------------------------------------------------

def bump_cargo(path, current, new):
    body = read(path)
    new_body = re.sub(
        r'(\[package\][^\[]*?\nversion\s*=\s*)"' + re.escape(current) + r'"',
        lambda m: m.group(1) + f'"{new}"',
        body, count=1, flags=re.DOTALL,
    )
    if new_body == body:
        raise SystemExit(f'failed to update [package].version in {path}')
    write(path, new_body)

def bump_dockerfile(path, current, new):
    body = read(path)
    pat = re.compile(
        r'(org\.opencontainers\.image\.version\s*=\s*)"'
        + re.escape(current) + r'"'
    )
    new_body, count = pat.subn(lambda m: m.group(1) + f'"{new}"', body)
    if count == 0:
        warn(f'no opencontainers.image.version="{current}" in {path} — skipping')
        return
    write(path, new_body)

def bump_values_yaml(path, dotted, current, new):
    """Update `<a>.<b>.<c>: "X"` for a dotted path. Walks the YAML
    by indentation depth (the chart consistently uses 2-space
    indents) and rewrites the leaf string in place."""
    body = read(path)
    keys = dotted.split('.')
    lines = body.split('\n')
    indent = 0
    depth = 0
    rewrote = False
    for i, line in enumerate(lines):
        stripped = line.lstrip(' ')
        line_indent = len(line) - len(stripped)
        if depth < len(keys) - 1:
            head = f'{keys[depth]}:'
            if line_indent == indent and stripped.startswith(head):
                depth += 1
                indent += 2
                continue
        else:
            head = f'{keys[depth]}:'
            if line_indent == indent and stripped.startswith(head):
                lines[i] = ' ' * indent + f'{keys[depth]}: "{new}"'
                rewrote = True
                break
    if not rewrote:
        warn(f'no {dotted} key in {path} — skipping')
        return
    write(path, '\n'.join(lines))

def bump_compose(path, image_name, current, new):
    body = read(path)
    pat = re.compile(
        r'(image:\s+' + re.escape(image_name) + r':)([\w.-]+)'
    )
    new_body, count = pat.subn(
        lambda m: m.group(1) + new if m.group(2) != new else m.group(0),
        body,
    )
    if count == 0:
        warn(f'no `image: {image_name}:*` line in {path} — skipping')
        return
    write(path, new_body)

def bump_chart_yaml(path, current, new):
    body = read(path)
    new_body = re.sub(
        r'^(version:\s*)' + re.escape(current) + r'\s*$',
        lambda m: m.group(1) + new,
        body, count=1, flags=re.MULTILINE,
    )
    if new_body == body:
        raise SystemExit(f'failed to update version: in {path}')
    write(path, new_body)

def add_changelog_stub(crate, new):
    if NO_CHANGELOG:
        print('  [--no-changelog] skipping CHANGELOG.md')
        return
    path = 'CHANGELOG.md'
    today = _dt.date.today().isoformat()
    if not os.path.exists(path):
        warn(f'{path} does not exist — skipping (create it manually)')
        return
    body = read(path)
    today_heading = f'## {today}'
    sub_section = (
        f'\n### {crate} {new}\n'
        f'- _TODO: replace this stub with the user-facing release notes._\n'
    )
    if today_heading in body:
        # Append the per-crate section under the existing date.
        idx = body.index(today_heading)
        end = body.find('\n## ', idx + len(today_heading))
        if end == -1: end = len(body)
        new_body = body[:end] + sub_section + body[end:]
    else:
        # Insert a new dated block above the most recent existing one.
        m = re.search(r'^## \d{4}-\d{2}-\d{2}', body, re.MULTILINE)
        if m:
            insert_at = m.start()
            new_body = (
                body[:insert_at]
                + f'{today_heading}\n{sub_section}\n---\n\n'
                + body[insert_at:]
            )
        else:
            new_body = body.rstrip() + f'\n\n---\n\n{today_heading}\n{sub_section}'
    write(path, new_body)

# ---- dispatch ------------------------------------------------------------

if target == 'chart':
    bump_chart_yaml(meta['chart_yaml'], current, new)
    add_changelog_stub('helm-chart', new)
else:
    bump_cargo(meta['cargo'], current, new)
    if meta.get('dockerfile'):
        bump_dockerfile(meta['dockerfile'], current, new)
    if meta.get('values_path'):
        bump_values_yaml(
            'deploy/helm/siphon/values.yaml',
            meta['values_path'], current, new,
        )
    if meta.get('compose_img'):
        bump_compose(
            'deploy/docker-compose.yml',
            meta['compose_img'], current, new,
        )
    add_changelog_stub(meta['crate'], new)

if target == 'core' and parse_semver(new)[0] > parse_semver(current)[0]:
    warn(
        'core MAJOR bump: every downstream crate (siphon, '
        'siphon-api, siphon-fs, siphon-launcher) needs at least a '
        'MINOR bump in the same wave per CLAUDE.md "core MAJOR '
        'cascades". Re-run this script for each.'
    )

if not DRY_RUN and target != 'chart':
    banner('cargo check (refresh Cargo.lock)')
    try:
        subprocess.run(['cargo', 'check', '-p', meta['crate'], '-q'], check=True)
    except subprocess.CalledProcessError as e:
        raise SystemExit(f'cargo check failed: {e}')

print('\n✔ done.')
PY
