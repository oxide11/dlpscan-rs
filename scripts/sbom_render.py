#!/usr/bin/env python3
"""Render `cargo tree` output as CycloneDX 1.6, and as a reviewable inventory.

Driven by scripts/generate-sbom.sh; not intended to be run directly.

Written here rather than pulling `cargo-cyclonedx` because the interesting
part of this SBOM is not the serialisation — it is the per-package feature
resolution that `cargo tree -p` does and `cargo metadata` does not. A tool
that got that wrong would produce a confident, wrong document, and the
serialisation it saves is a hundred lines.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Components with a C or C++ implementation underneath. Rust's memory-safety
# guarantees stop at these, and they all sit on the path that parses
# attacker-supplied files, so an auditor should see them called out rather
# than buried among six hundred pure-Rust crates.
NATIVE_CODE = {
    "libsqlite3-sys": "bundled SQLite (C), reached via rusqlite for .sqlite extraction",
    "unrar_sys": "UnRAR (C++), reached via unrar for .rar extraction",
    "unrar": "safe wrapper over unrar_sys",
    "rusqlite": "safe wrapper over libsqlite3-sys",
    "ring": "assembly + C crypto primitives, reached via rustls",
}

# A backtracking regex engine. Worth flagging in a DLP scanner specifically,
# because the main scan path deliberately uses `regex`, whose automaton
# construction rules out catastrophic backtracking. Anything that reaches a
# backtracking engine with attacker-controlled input reintroduces that risk.
BACKTRACKING_REGEX = {"fancy-regex"}

# `cargo tree --format "{p}|{l}|{r}"` emits, for the package field:
#   name v1.2.3
#   name v1.2.3 (proc-macro)
#   name v1.2.3 (/abs/path)      <- workspace member
#   name v1.2.3 (*)              <- already shown elsewhere in the tree
PKG_RE = re.compile(r"^(?P<name>[A-Za-z0-9_.+-]+) v(?P<version>[^\s]+)(?P<rest>.*)$")


def parse(path: Path) -> list[dict]:
    seen: dict[tuple[str, str], dict] = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        pkg_field, license_field, repo_field = parts[0], parts[1], parts[2]
        m = PKG_RE.match(pkg_field.strip())
        if not m:
            continue
        name = m.group("name")
        version = m.group("version")
        rest = m.group("rest")
        key = (name, version)
        if key in seen:
            continue
        seen[key] = {
            "name": name,
            "version": version,
            # cargo prints "(/path)" for workspace members. Recording this
            # separates first-party code from third-party in the document,
            # which is the first question anyone asks of an SBOM.
            "first_party": rest.strip().startswith("(/"),
            "proc_macro": "(proc-macro)" in rest,
            "license": license_field.strip(),
            "repository": repo_field.strip(),
        }
    return [seen[k] for k in sorted(seen)]


def normalise_licence(raw: str) -> str:
    """Turn crates.io's older `/` separator into a valid SPDX expression.

    76 components in this workspace declare `MIT/Apache-2.0` and similar.
    The slash form predates SPDX expressions in Cargo and is not valid SPDX,
    so emitting it verbatim as a CycloneDX `expression` produces a document
    that a consumer is entitled to reject — the licence would read as
    unparseable rather than as permissive, which is the opposite of what an
    SBOM is for. Cargo has always meant it as OR.
    """
    if "/" not in raw:
        return raw
    return " OR ".join(part.strip() for part in raw.split("/") if part.strip())


def component(c: dict) -> dict:
    out = {
        "type": "library",
        "name": c["name"],
        "version": c["version"],
        # Package URL: the identifier vulnerability scanners actually match on.
        "purl": f"pkg:cargo/{c['name']}@{c['version']}",
        "scope": "required",
    }
    if c["license"]:
        expr = normalise_licence(c["license"])
        # CycloneDX wants `expression` for compound SPDX ("MIT OR Apache-2.0")
        # and `id` for a single licence. Emitting a compound string as an id
        # produces a document that validates but that no tool can evaluate.
        if any(op in expr for op in (" OR ", " AND ", " WITH ")):
            out["licenses"] = [{"expression": expr}]
        else:
            out["licenses"] = [{"license": {"id": expr}}]
    else:
        # Recorded as unknown rather than omitted. A missing licences array
        # reads as "not checked"; this reads as "checked, none declared",
        # which is a finding.
        out["licenses"] = [{"license": {"name": "NOASSERTION"}}]
    if c["repository"]:
        out["externalReferences"] = [{"type": "vcs", "url": c["repository"]}]

    props = []
    if c["first_party"]:
        props.append({"name": "siphon:first-party", "value": "true"})
    if c["proc_macro"]:
        props.append({"name": "siphon:proc-macro", "value": "true"})
    if c["name"] in NATIVE_CODE:
        props.append({"name": "siphon:native-code", "value": NATIVE_CODE[c["name"]]})
    if c["name"] in BACKTRACKING_REGEX:
        props.append(
            {
                "name": "siphon:backtracking-regex",
                "value": "backtracking engine; the main scan path uses `regex` to rule out "
                "catastrophic backtracking",
            }
        )
    if props:
        out["properties"] = props
    return out


def render_bom(pkg: str, comps: list[dict], target: str, timestamp: bool) -> str:
    root = next((c for c in comps if c["name"] == pkg), None)
    version = root["version"] if root else "0.0.0"

    metadata: dict = {
        "component": {
            "type": "application",
            "name": pkg,
            "version": version,
            "purl": f"pkg:cargo/{pkg}@{version}",
        },
        "properties": [
            {"name": "siphon:target", "value": target},
            {
                "name": "siphon:resolution",
                "value": "per-package (cargo tree -p); workspace-wide resolution "
                "unifies features and over-reports components",
            },
            {"name": "siphon:edges", "value": "normal only; dev- and build-dependencies excluded"},
        ],
        "tools": {"components": [{"type": "application", "name": "scripts/generate-sbom.sh"}]},
    }
    if timestamp:
        from datetime import datetime, timezone

        metadata["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": metadata,
        # The root package is the metadata component, so it is not repeated
        # in the component list.
        "components": [component(c) for c in comps if c["name"] != pkg],
    }
    return json.dumps(bom, indent=2, sort_keys=False) + "\n"


def render_summary(input_dir: Path, target: str) -> str:
    rows = []
    all_native: dict[str, set[str]] = {}
    all_backtracking: dict[str, set[str]] = {}
    licenses: dict[str, int] = {}
    unlicensed: set[str] = set()

    for raw in sorted(input_dir.glob("*.raw")):
        pkg = raw.stem
        comps = parse(raw)
        third_party = [c for c in comps if not c["first_party"]]
        rows.append((pkg, len(comps), len(third_party)))
        for c in comps:
            if c["name"] in NATIVE_CODE:
                all_native.setdefault(c["name"], set()).add(pkg)
            if c["name"] in BACKTRACKING_REGEX:
                all_backtracking.setdefault(c["name"], set()).add(pkg)
            if not c["first_party"]:
                lic = normalise_licence(c["license"]) if c["license"] else "NOASSERTION"
                licenses[lic] = licenses.get(lic, 0) + 1
                if not c["license"]:
                    unlicensed.add(f"{c['name']} {c['version']}")

    out = []
    out.append("# Bill of materials\n")
    out.append(
        "Generated by `scripts/generate-sbom.sh`. CycloneDX 1.6 documents sit\n"
        "beside this file, one per shipped artifact.\n"
    )
    out.append(
        "**There is no single BOM for this repository.** Each artifact links a\n"
        "different closure, and the differences matter: `siphon-api` links none of\n"
        "rusqlite, unrar, rxing or the image codecs, while `siphon-fs` and\n"
        "`siphon-milter` link all of them. A workspace-wide document would claim\n"
        "siphon-api ships a bundled SQLite and a C RAR decoder it has never\n"
        "contained.\n"
    )
    out.append(
        f"Resolved per package for `{target}`, normal edges only — dev- and\n"
        "build-dependencies are not components of a shipped binary. Note that\n"
        "`cargo metadata` and `cargo tree --workspace` unify features across\n"
        "members and report that false picture; `cargo tree -p` does not.\n"
    )

    out.append("## Artifacts\n")
    out.append("| Artifact | Components | Third-party |")
    out.append("|---|---|---|")
    for pkg, total, third in sorted(rows, key=lambda r: -r[1]):
        out.append(f"| `{pkg}` | {total} | {third} |")
    out.append("")

    out.append("## Components with native code\n")
    out.append(
        "Rust's memory-safety guarantees stop here, and each of these sits on the\n"
        "path that parses attacker-supplied files.\n"
    )
    if all_native:
        out.append("| Component | Why it is here | Shipped in |")
        out.append("|---|---|---|")
        for name in sorted(all_native):
            where = ", ".join(f"`{p}`" for p in sorted(all_native[name]))
            out.append(f"| `{name}` | {NATIVE_CODE[name]} | {where} |")
    else:
        out.append("_None._")
    out.append("")

    if all_backtracking:
        out.append("## Backtracking regex engines\n")
        out.append(
            "The scan path deliberately uses `regex`, whose automaton construction\n"
            "rules out catastrophic backtracking. A backtracking engine reachable\n"
            "from attacker-controlled input reintroduces that risk.\n"
        )
        out.append("| Component | Shipped in |")
        out.append("|---|---|")
        for name in sorted(all_backtracking):
            where = ", ".join(f"`{p}`" for p in sorted(all_backtracking[name]))
            out.append(f"| `{name}` | {where} |")
        out.append("")

    out.append("## Licences\n")
    out.append("Across all third-party components in all artifacts, counted per artifact.\n")
    out.append("| Licence | Occurrences |")
    out.append("|---|---|")
    for lic, n in sorted(licenses.items(), key=lambda kv: (-kv[1], kv[0])):
        out.append(f"| `{lic}` | {n} |")
    out.append("")
    if unlicensed:
        out.append("### Components declaring no licence\n")
        out.append(
            "Recorded as `NOASSERTION` in the CycloneDX documents. Checked and\n"
            "found absent, which is different from not having looked.\n"
        )
        for u in sorted(unlicensed):
            out.append(f"- `{u}`")
        out.append("")

    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package")
    ap.add_argument("--input")
    ap.add_argument("--input-dir")
    ap.add_argument("--target", required=True)
    ap.add_argument("--timestamp", action="store_true")
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    if args.summary:
        sys.stdout.write(render_summary(Path(args.input_dir), args.target))
        return 0

    comps = parse(Path(args.input))
    sys.stdout.write(render_bom(args.package, comps, args.target, args.timestamp))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
