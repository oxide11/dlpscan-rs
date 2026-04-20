#!/usr/bin/env bash
# Re-inline docs/wireframes/siphon-shared.{css,js} into siphon-ir.html.
#
# siphon-ir.html must be self-contained so it works from file://
# (Safari + Chrome both block <link href> and <script src> cross-
# origin loads on that protocol). The shared files are still the
# source of truth; run this script after editing either of them so
# the IR console picks up the change.
#
# Usage: ./docs/wireframes/sync-shared-into-ir.sh
#        (runs from any cwd; resolves its own directory)

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

python3 <<'PY'
with open('siphon-shared.css') as f: css = f.read()
with open('siphon-shared.js')  as f: js  = f.read()
with open('siphon-ir.html')    as f: html = f.read()

import re

# Replace the <style>...</style> block (first one) with fresh CSS.
# Use a lambda replacement to avoid re.sub treating backslashes in the
# payload (e.g. regex literals, `\d`, `\w`) as backref escapes.
html = re.sub(
    r'<style>\n.*?\n</style>',
    lambda _m: '<style>\n' + css.rstrip() + '\n</style>',
    html,
    count=1,
    flags=re.DOTALL,
)

# Replace the siphon-shared.js inline block. The marker line
# `// ─── siphon-shared.js ` (copied verbatim from the source file's
# header) makes this block unambiguous even when many <script> blocks
# are present.
html = re.sub(
    r'<script>\n// ─── siphon-shared\.js .*?\n</script>',
    lambda _m: '<script>\n' + js.rstrip() + '\n</script>',
    html,
    count=1,
    flags=re.DOTALL,
)

with open('siphon-ir.html', 'w') as f:
    f.write(html)

print('re-inlined siphon-shared.{css,js} into siphon-ir.html')
PY
