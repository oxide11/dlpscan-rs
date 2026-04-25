#!/usr/bin/env bash
# Re-inline docs/wireframes/siphon-shared.{css,js} into both
# siphon-c2.html and siphon-ir.html.
#
# Both consoles must be self-contained so they work from file://
# (Safari + Chrome both block <link href> and <script src> cross-
# origin loads on that protocol). The shared files are still the
# source of truth; run this script after editing either of them so
# the consoles pick up the change.
#
# Usage: ./docs/wireframes/sync-shared.sh
#        (runs from any cwd; resolves its own directory)

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

python3 <<'PY'
import re

with open('siphon-shared.css') as f: css = f.read()
with open('siphon-shared.js')  as f: js  = f.read()

TARGETS = ['siphon-c2.html', 'siphon-ir.html']

for path in TARGETS:
    with open(path) as f: html = f.read()

    # Replace the first <style>...</style> with fresh CSS. Lambda
    # avoids re.sub treating backslashes in the payload (regex
    # literals with \d, \w, etc.) as backref escapes.
    html = re.sub(
        r'<style>\n.*?\n</style>',
        lambda _m: '<style>\n' + css.rstrip() + '\n</style>',
        html,
        count=1,
        flags=re.DOTALL,
    )

    # Replace the inlined siphon-shared.js block. The marker line
    # `// ─── siphon-shared.js ` (verbatim from the source file's
    # header) makes this block unambiguous even when many <script>
    # blocks are present in the same file.
    html = re.sub(
        r'<script>\n// ─── siphon-shared\.js .*?\n</script>',
        lambda _m: '<script>\n' + js.rstrip() + '\n</script>',
        html,
        count=1,
        flags=re.DOTALL,
    )

    with open(path, 'w') as f: f.write(html)
    print(f're-inlined siphon-shared.{{css,js}} into {path}')
PY
