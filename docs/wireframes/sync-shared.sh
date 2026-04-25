#!/usr/bin/env bash
# Re-inline docs/wireframes/siphon-shared.{css,js} and any extracted
# surface files (c2/surfaces/*.jsx, ir/surfaces/*.jsx) into the
# corresponding HTML console.
#
# Both consoles must be self-contained so they work from file://
# (Safari + Chrome both block <link href> and <script src> cross-
# origin loads on that protocol). The HTML files are the runtime
# artifact; the .jsx / .js / .css files are the editable source of
# truth. Run this script after editing any of them.
#
# Usage: ./docs/wireframes/sync-shared.sh
#        (runs from any cwd; resolves its own directory)

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

python3 <<'PY'
import os, re

with open('siphon-shared.css') as f: css = f.read()
with open('siphon-shared.js')  as f: js  = f.read()

# Per-console surface roots. Each .jsx file is matched against
# `<!-- @sync-surface: NAME -->`...`<!-- @end-sync-surface: NAME -->`
# in the HTML, and the script block between them is regenerated
# from the file content.
TARGETS = [
    ('siphon-c2.html', 'c2/surfaces'),
    ('siphon-ir.html', 'ir/surfaces'),
]

def load_surfaces(root):
    """Return {name: contents} for every .jsx under `root`."""
    if not os.path.isdir(root):
        return {}
    out = {}
    for fn in sorted(os.listdir(root)):
        if not fn.endswith('.jsx'):
            continue
        name = fn[:-4]
        with open(os.path.join(root, fn)) as f:
            out[name] = f.read()
    return out

for path, surface_dir in TARGETS:
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

    # Replace each surface marker block. The pattern matches the
    # whole stanza (open marker → script → close marker) and we
    # build the replacement from scratch — no regex backreferences,
    # since the lambda passed to re.sub returns its string verbatim.
    for name, body in load_surfaces(surface_dir).items():
        open_tag  = f'<!-- @sync-surface: {name} -->'
        close_tag = f'<!-- @end-sync-surface: {name} -->'
        marker_re = re.compile(
            re.escape(open_tag) + r'\n'
            + r'<script type="text/babel" data-presets="react">\n.*?\n</script>\n'
            + re.escape(close_tag),
            re.DOTALL,
        )
        replacement = (
            open_tag + '\n'
            + '<script type="text/babel" data-presets="react">\n'
            + f'/* GENERATED — edit {surface_dir}/{name}.jsx and run sync-shared.sh */\n'
            + body.rstrip() + '\n'
            + '</script>\n'
            + close_tag
        )
        new_html, count = marker_re.subn(lambda _m, r=replacement: r, html, count=1)
        if count == 0:
            print(f'  warn: no @sync-surface: {name} marker in {path} — skipping')
        else:
            html = new_html
            print(f'  inlined {surface_dir}/{name}.jsx into {path}')

    with open(path, 'w') as f: f.write(html)
    print(f're-inlined siphon-shared.{{css,js}} + surfaces into {path}')
PY
