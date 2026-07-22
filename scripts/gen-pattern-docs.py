#!/usr/bin/env python3
"""Regenerate docs/PATTERNS.md and docs/KEYWORDS.md from siphon-core sources.

Parses `crates/siphon-core/src/patterns/mod.rs` and
`crates/siphon-core/src/context/keywords.rs` and rewrites the two inventory
documents so they always reflect what the scanner actually runs.

The PatternDef `specificity` / `context_required` fields are asserted against
the `pattern_specificity()` / `is_context_required()` maps in models.rs (the
values the scanner uses at runtime via the `effective_*` helpers) so this
script fails loudly instead of documenting a drifted value. The same
invariant is enforced by tests/audit_spec.rs.

Usage: python3 scripts/gen-pattern-docs.py [--check]
  --check   exit 1 if the generated docs differ from what's on disk
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATTERNS_RS = ROOT / "crates/siphon-core/src/patterns/mod.rs"
KEYWORDS_RS = ROOT / "crates/siphon-core/src/context/keywords.rs"
MODELS_RS = ROOT / "crates/siphon-core/src/models.rs"
PATTERNS_MD = ROOT / "docs/PATTERNS.md"
KEYWORDS_MD = ROOT / "docs/KEYWORDS.md"


def strip_comments(text: str) -> str:
    """Drop full-line // comments. String literals never span lines here."""
    return "\n".join(
        ln for ln in text.splitlines() if not ln.lstrip().startswith("//")
    )


def unrust(lit: str) -> str:
    """Decode a Rust string literal (raw, raw-hash, or plain)."""
    if lit.startswith('r#"'):
        return lit[3:-2]
    if lit.startswith('r"'):
        return lit[2:-1]
    return lit[1:-1].replace('\\"', '"').replace("\\\\", "\\")


PAT_RE = re.compile(
    r'PatternDef\s*\{\s*'
    r'category:\s*"((?:[^"\\]|\\.)*)",\s*'
    r'sub_category:\s*"((?:[^"\\]|\\.)*)",\s*'
    r'regex:\s*(r#".*?"#|r"[^"]*"|"(?:[^"\\]|\\.)*"),\s*'
    r'case_insensitive:\s*(?:true|false),\s*'
    r'specificity:\s*([0-9.]+),\s*'
    r'context_required:\s*(true|false),\s*'
    r'\}',
    re.S,
)

KW_RE = re.compile(
    r'\(\s*"((?:[^"\\]|\\.)*)",\s*"((?:[^"\\]|\\.)*)",\s*ContextEntry\s*\{\s*'
    r'keywords:\s*&\[(.*?)\],\s*'
    r'distance:\s*(\d+),\s*\}\s*,?\s*\)',
    re.S,
)

STR_LIT = re.compile(r'"((?:[^"\\]|\\.)*)"')


def parse_patterns():
    src = strip_comments(PATTERNS_RS.read_text(encoding="utf-8"))
    n_defs = src.count("PatternDef {")
    out = {}
    for m in PAT_RE.finditer(src):
        cat, sub, rx, spec, ctx = m.groups()
        out[(cat, sub)] = {
            "regex": unrust(rx),
            "spec": float(spec),
            "ctx": ctx == "true",
        }
    if len(out) != n_defs:
        sys.exit(
            f"parse error: matched {len(out)} PatternDef blocks but source "
            f"contains {n_defs}"
        )
    return out


def parse_keywords():
    src = strip_comments(KEYWORDS_RS.read_text(encoding="utf-8"))
    n_entries = src.count("ContextEntry {")
    out = {}
    for m in KW_RE.finditer(src):
        cat, sub, kws, dist = m.groups()
        out[(cat, sub)] = {
            "keywords": [unrust(f'"{s}"') for s in STR_LIT.findall(kws)],
            "distance": int(dist),
        }
    if len(out) != n_entries:
        sys.exit(
            f"parse error: matched {len(out)} ContextEntry blocks but source "
            f"contains {n_entries}"
        )
    return out


def parse_models():
    """Return (spec_map, default_spec, ctx_set) from models.rs."""
    src = MODELS_RS.read_text(encoding="utf-8")
    default = float(
        re.search(r"DEFAULT_SPECIFICITY: f64 = ([0-9.]+)", src).group(1)
    )
    m = re.search(
        r"pub fn pattern_specificity.*?\n(.*?)\n\s*_ => DEFAULT_SPECIFICITY,",
        src,
        re.S,
    )
    body = strip_comments(m.group(1))
    spec_map = {}
    for arm in re.finditer(
        r'((?:"(?:[^"\\]|\\.)*"\s*\|\s*)*"(?:[^"\\]|\\.)*")\s*=>\s*\{?\s*([0-9.]+)',
        body,
    ):
        keys, val = arm.groups()
        for k in STR_LIT.findall(keys):
            spec_map[k] = float(val)
    m = re.search(
        r"pub fn is_context_required.*?matches!\(\s*sub_category,(.*?)\)\s*\}",
        src,
        re.S,
    )
    ctx_set = set(STR_LIT.findall(strip_comments(m.group(1))))
    return spec_map, default, ctx_set


def check_drift(patterns, spec_map, default, ctx_set):
    """Mirror tests/audit_spec.rs: PatternDef fields must equal the maps."""
    errors = []
    subs = {sub for _, sub in patterns}
    for key in spec_map:
        if key not in subs:
            errors.append(
                f"pattern_specificity() key {key!r} matches no pattern "
                f"sub_category (dead key — the pattern it was meant for "
                f"falls back to DEFAULT_SPECIFICITY)"
            )
    for key in ctx_set:
        if key not in subs:
            errors.append(
                f"is_context_required() entry {key!r} matches no pattern "
                f"sub_category"
            )
    for (cat, sub), v in patterns.items():
        map_spec = spec_map.get(sub, default)
        if abs(map_spec - v["spec"]) > 0.001:
            errors.append(
                f"{cat} / {sub}: PatternDef.specificity={v['spec']} but "
                f"pattern_specificity()={map_spec}"
            )
        if (sub in ctx_set) != v["ctx"]:
            errors.append(
                f"{cat} / {sub}: PatternDef.context_required={v['ctx']} but "
                f"is_context_required()={sub in ctx_set}"
            )
    if errors:
        print("drift between patterns/mod.rs and models.rs:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)


def esc(cell: str) -> str:
    """Escape table pipes inside a markdown cell."""
    return cell.replace("|", "\\|")


def by_category(entries):
    cats = {}
    for (cat, sub), v in entries.items():
        cats.setdefault(cat, []).append((sub, v))
    return {cat: sorted(rows) for cat, rows in sorted(cats.items())}


def gen_patterns_md(patterns):
    cats = by_category(patterns)
    lines = [
        "# PATTERNS.md",
        "",
        "Complete inventory of all patterns in dlpscan.",
        f"**{len(patterns)} patterns** across **{len(cats)} categories**.",
        "",
        "Each pattern includes:",
        "- **Regex** -- the detection pattern",
        "- **Specificity** -- base confidence score (0.0-1.0); higher means fewer false positives",
        "- **Context Required** -- if Yes, the pattern is suppressed unless a context keyword appears nearby",
        "",
        "> See [KEYWORDS.md](KEYWORDS.md) for the context keywords that boost or gate each pattern.",
        "",
        "This file is generated by `scripts/gen-pattern-docs.py` from",
        "`crates/siphon-core/src/patterns/mod.rs` — do not edit by hand.",
        "",
        "### Specificity scale",
        "",
        "| Range | Meaning | Examples |",
        "|---|---|---|",
        "| 0.85 -- 1.0 | High confidence, few false positives | JWT, AWS keys, Track Data, Credit Cards |",
        "| 0.50 -- 0.84 | Moderate confidence, context helps | IBAN, Email, Phone, Crypto addresses |",
        "| 0.20 -- 0.49 | Low confidence, context recommended | Bank accounts, dates, check numbers |",
        "| 0.00 -- 0.19 | Very low, context required | Cardholder name, OFAC SDN |",
        "",
        "---",
        "",
    ]
    for cat, rows in cats.items():
        lines.append(f"## {cat} ({len(rows)} patterns)")
        lines.append("")
        lines.append("| Pattern Name | Regex | Specificity | Context Required |")
        lines.append("|---|---|---:|:---:|")
        for sub, v in rows:
            ctx = "Yes" if v["ctx"] else "No"
            lines.append(
                f"| {esc(sub)} | `{esc(v['regex'])}` | {v['spec']:.2f} | {ctx} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def gen_keywords_md(keywords):
    cats = by_category(keywords)
    total = sum(len(v["keywords"]) for v in keywords.values())
    lines = [
        "# KEYWORDS.md",
        "",
        "Complete inventory of all context keywords used by dlpscan for",
        "proximity-based detection.",
        "",
        f"**{len(keywords)} keyword groups** across **{len(cats)} categories** — "
        f"**{total} keywords** (English, French, Spanish, German, Italian, Portuguese).",
        "",
        "## How context matching works",
        "",
        "dlpscan uses an [Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)",
        "automaton to scan the input text for all keywords in a single O(n) pass.",
        "When a keyword is found within the configured **distance** (in characters)",
        "of a regex match, the match receives a confidence boost of +0.20",
        "(capped at 1.0). Patterns marked as **context-required** are suppressed",
        "entirely unless a keyword is found nearby.",
        "",
        "Keywords are provided in 6 languages: English, French/French-Canadian,",
        "Spanish, German, Italian, and Portuguese.",
        "",
        "> See [PATTERNS.md](PATTERNS.md) for the corresponding regex patterns.",
        "",
        "This file is generated by `scripts/gen-pattern-docs.py` from",
        "`crates/siphon-core/src/context/keywords.rs` — do not edit by hand.",
        "",
        "---",
        "",
    ]
    for cat, rows in cats.items():
        lines.append(f"## {cat} ({len(rows)} keyword groups)")
        lines.append("")
        lines.append("| Pattern | Keywords | Distance |")
        lines.append("|---|---|---:|")
        for sub, v in rows:
            kws = ", ".join(f"`{esc(k)}`" for k in v["keywords"])
            lines.append(f"| {esc(sub)} | {kws} | {v['distance']} |")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def main():
    check = "--check" in sys.argv[1:]
    patterns = parse_patterns()
    keywords = parse_keywords()
    spec_map, default, ctx_set = parse_models()
    check_drift(patterns, spec_map, default, ctx_set)

    pk, kk = set(patterns), set(keywords)
    if pk != kk:
        for k in sorted(pk - kk):
            print(f"warning: pattern {k} has no keyword group", file=sys.stderr)
        for k in sorted(kk - pk):
            print(f"warning: keyword group {k} has no pattern", file=sys.stderr)

    outputs = {
        PATTERNS_MD: gen_patterns_md(patterns),
        KEYWORDS_MD: gen_keywords_md(keywords),
    }
    dirty = []
    for path, content in outputs.items():
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if current != content:
            dirty.append(path)
            if not check:
                path.write_text(content, encoding="utf-8")
    if check and dirty:
        names = ", ".join(p.name for p in dirty)
        sys.exit(f"stale (run scripts/gen-pattern-docs.py): {names}")
    for path in outputs:
        state = (
            "stale" if check and path in dirty
            else "ok" if check
            else "written" if path in dirty
            else "unchanged"
        )
        print(f"{path.relative_to(ROOT)}: {state}")


if __name__ == "__main__":
    main()
