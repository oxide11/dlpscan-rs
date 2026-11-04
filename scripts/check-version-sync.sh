#!/usr/bin/env bash
# Fail-fast check: every downstream declaration of a crate's version
# (Dockerfile LABEL, Helm image tag, compose tag) matches the crate's
# own Cargo.toml. Mirrors the "Lockstep updates within one crate"
# table in CLAUDE.md and the dispatch in scripts/bump-version.sh.
#
# What this enforces:
#   * crates/siphon-api/Cargo.toml    == Dockerfile.api LABEL
#                                     == values.yaml `api.image.tag`
#                                     == docker-compose.yml `siphon-api:VER`
#   * crates/siphon-fs/Cargo.toml     == Dockerfile.fs LABEL
#                                     == values.yaml `fs.image.tag`
#                                     == docker-compose.yml `siphon-fs:VER`
#   * Cargo.toml (root `siphon`)      == console/package.json `version`
#                                     == Chart.yaml `appVersion`
#
# What this deliberately does NOT enforce: per-crate SemVer is the
# project's policy (see CLAUDE.md "Versioning"), so siphon-core,
# siphon-api, siphon-fs, siphon-launcher, and the root crate all carry
# independent versions. The previous version of this script required
# them to be identical and would fail every PR — that policy was
# reverted in favor of per-crate SemVer but this script was never
# updated.
#
# Runs locally before a release wave and in .github/workflows/ci.yml.

set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

fail=0
checks=0

cargo_version() {
    # First `version = "X.Y.Z"` after the `[package]` header — anchored
    # past the section break so a `[dependencies]` block with a same-
    # named entry can't shadow the package version.
    awk '
        /^\[package\]/ { in_pkg = 1; next }
        /^\[/ { in_pkg = 0 }
        in_pkg && /^version[[:space:]]*=/ {
            gsub(/[^0-9.]/, "")
            print
            exit
        }
    ' "$1"
}

cargo_name() {
    # The package's own name, anchored past the section break for the same
    # reason cargo_version is: a [dependencies] entry must not shadow it.
    awk '
        /^\[package\]/ { in_pkg = 1; next }
        /^\[/ { in_pkg = 0 }
        in_pkg && /^name[[:space:]]*=/ {
            gsub(/^name[[:space:]]*=[[:space:]]*"|"[[:space:]]*$/, "")
            print
            exit
        }
    ' "$1"
}

# The version Cargo.lock records for a workspace member. Workspace members
# appear as an ordinary [[package]] block carrying no checksum, so this is a
# plain lookup of the version line inside the block whose name matches.
lock_version() {
    awk -v want="$1" '
        $0 == "[[package]]" { n = ""; next }
        /^name[[:space:]]*=/ {
            n = $0
            gsub(/^name[[:space:]]*=[[:space:]]*"|"[[:space:]]*$/, "", n)
            next
        }
        /^version[[:space:]]*=/ {
            if (n == want) {
                v = $0
                gsub(/^version[[:space:]]*=[[:space:]]*"|"[[:space:]]*$/, "", v)
                print v
                exit
            }
        }
    ' Cargo.lock
}

check() {
    local label="$1" expected="$2" actual="$3"
    checks=$((checks + 1))
    if [[ "${actual}" == "${expected}" ]]; then
        printf "  ok   %-55s %s\n" "${label}" "${actual}"
    else
        printf "  MISS %-55s %s (expected %s)\n" "${label}" "${actual}" "${expected}"
        fail=$((fail + 1))
    fi
}

# ---------------------------------------------------------------------------
# siphon-api lockstep
# ---------------------------------------------------------------------------
api_ver="$(cargo_version crates/siphon-api/Cargo.toml)"
echo "siphon-api ${api_ver}"

api_dockerfile_ver="$(awk -F\" '/opencontainers\.image\.version/{print $2; exit}' deploy/Dockerfile.api)"
check "  deploy/Dockerfile.api LABEL"              "${api_ver}" "${api_dockerfile_ver}"

# `api.image.tag` lives two levels deep in values.yaml; awk walks the
# block depth-first by tracking the `api:` header and the first
# `image:` under it.
api_values_tag="$(awk '
    /^api:/ { in_api = 1; next }
    /^[a-z]/ { in_api = 0 }
    in_api && /^  image:/ { in_image = 1; next }
    in_api && /^  [a-z]/ { in_image = 0 }
    in_api && in_image && /^    tag:/ {
        gsub(/[" ]|tag:/, "")
        print
        exit
    }
' deploy/helm/siphon/values.yaml)"
check "  deploy/helm/siphon/values.yaml api.image.tag" "${api_ver}" "${api_values_tag}"

api_compose_ver="$(awk -F: '/image:[[:space:]]+siphon-api:/{gsub(/[[:space:]]/,"",$3); print $3; exit}' deploy/docker-compose.yml)"
check "  deploy/docker-compose.yml siphon-api"     "${api_ver}" "${api_compose_ver}"

# ---------------------------------------------------------------------------
# siphon-fs lockstep
# ---------------------------------------------------------------------------
fs_ver="$(cargo_version crates/siphon-fs/Cargo.toml)"
echo "siphon-fs ${fs_ver}"

fs_dockerfile_ver="$(awk -F\" '/opencontainers\.image\.version/{print $2; exit}' deploy/Dockerfile.fs)"
check "  deploy/Dockerfile.fs LABEL"               "${fs_ver}" "${fs_dockerfile_ver}"

fs_values_tag="$(awk '
    /^fs:/ { in_fs = 1; next }
    /^[a-z]/ { in_fs = 0 }
    in_fs && /^  image:/ { in_image = 1; next }
    in_fs && /^  [a-z]/ { in_image = 0 }
    in_fs && in_image && /^    tag:/ {
        gsub(/[" ]|tag:/, "")
        print
        exit
    }
' deploy/helm/siphon/values.yaml)"
check "  deploy/helm/siphon/values.yaml fs.image.tag"  "${fs_ver}" "${fs_values_tag}"

fs_compose_ver="$(awk -F: '/image:[[:space:]]+siphon-fs:/{gsub(/[[:space:]]/,"",$3); print $3; exit}' deploy/docker-compose.yml)"
check "  deploy/docker-compose.yml siphon-fs"      "${fs_ver}" "${fs_compose_ver}"

# ---------------------------------------------------------------------------
# siphon-smtp lockstep
# ---------------------------------------------------------------------------
# Covered from the crate's first release rather than retrofitted. siphon-icap
# shipped without coverage here and its Dockerfile LABEL and compose tag have
# had nothing keeping them honest since; adding a service to this script is
# cheap on day one and archaeology later.
#
# No values.yaml entry: the Helm chart does not deploy the milter, matching
# siphon-icap. New protocol services ship in compose first.
smtp_ver="$(cargo_version crates/siphon-smtp/Cargo.toml)"
echo "siphon-smtp ${smtp_ver}"

smtp_dockerfile_ver="$(awk -F\" '/opencontainers\.image\.version/{print $2; exit}' deploy/Dockerfile.smtp)"
check "  deploy/Dockerfile.smtp LABEL"           "${smtp_ver}" "${smtp_dockerfile_ver}"

smtp_compose_ver="$(awk -F: '/image:[[:space:]]+siphon-smtp:/{gsub(/[[:space:]]/,"",$3); print $3; exit}' deploy/docker-compose.yml)"
check "  deploy/docker-compose.yml siphon-smtp"  "${smtp_ver}" "${smtp_compose_ver}"

# ---------------------------------------------------------------------------
# root siphon CLI + console + Helm appVersion lockstep
# ---------------------------------------------------------------------------
# The root crate's version is the "headline" release label. Chart.yaml's
# own comment pins appVersion to the root crate, and the console ships
# alongside the CLI so console/package.json tracks it too.
root_ver="$(cargo_version Cargo.toml)"
echo "siphon (root) ${root_ver}"

console_ver="$(awk -F\" '/^[[:space:]]*"version":/{print $4; exit}' console/package.json)"
check "  console/package.json"                     "${root_ver}" "${console_ver}"

chart_app_ver="$(awk -F\" '/^appVersion:/{print $2; exit}' deploy/helm/siphon/Chart.yaml)"
check "  deploy/helm/siphon/Chart.yaml appVersion" "${root_ver}" "${chart_app_ver}"

# ---------------------------------------------------------------------------
# Rust toolchain lockstep
# ---------------------------------------------------------------------------
# CLAUDE.md pins the toolchain in five places that must move together:
# rust-toolchain.toml, every crate's `rust-version`, the CI workflows, and
# the Dockerfile base images. The Dockerfiles matter most and were the ones
# nothing checked: rust-toolchain.toml is NOT copied into the image build
# (see the COPY list in deploy/Dockerfile.api), so there is no rustup
# override inside the container — the base image tag alone decides which
# compiler builds the shipped binary. When it drifts from the CI toolchain,
# production artifacts are built by a compiler that CI never tested against,
# silently. That is exactly what happened: the Dockerfiles sat on 1.96 while
# everything else was on 1.95.
rust_toolchain_ver="$(awk -F\" '/^channel[[:space:]]*=/{print $2; exit}' rust-toolchain.toml)"
echo "rust toolchain ${rust_toolchain_ver}"

for f in Cargo.toml crates/*/Cargo.toml; do
    rv="$(awk -F\" '/^rust-version[[:space:]]*=/{print $2; exit}' "$f")"
    [[ -n "${rv}" ]] && check "  ${f} rust-version" "${rust_toolchain_ver}" "${rv}"
done

for f in deploy/Dockerfile deploy/Dockerfile.api deploy/Dockerfile.fs; do
    bv="$(awk '/^FROM rust:/{sub(/^FROM rust:/, ""); sub(/-.*$/, ""); print; exit}' "$f")"
    check "  ${f} base image" "${rust_toolchain_ver}" "${bv}"
done

# CI workflows pin the toolchain explicitly per job.
while read -r wf ver; do
    check "  ${wf} toolchain" "${rust_toolchain_ver}" "${ver}"
done < <(grep -hoE '^\s*toolchain: "[0-9.]+"' -r .github/workflows/*.yml >/dev/null 2>&1; \
         grep -rlE '^\s*toolchain: "[0-9.]+"' .github/workflows/*.yml 2>/dev/null | while read -r f; do
             grep -oE '^\s*toolchain: "[0-9.]+"' "$f" | grep -oE '[0-9.]+' | sort -u | while read -r v; do
                 echo "${f} ${v}"
             done
         done)

# ---------------------------------------------------------------------------
# Postgres client-auth policy lockstep
# ---------------------------------------------------------------------------
# One policy, two consumers: compose mounts deploy/postgres/pg_hba.conf
# directly, and the Helm chart can only read files inside its own directory,
# so it carries a copy. A drifted copy is a database that admits something
# the other deployment refuses — checked byte-for-byte, like a version.
checks=$((checks + 1))
if cmp -s deploy/postgres/pg_hba.conf deploy/helm/siphon/files/pg_hba.conf; then
    printf "  ok   %-55s %s\n" "deploy/helm/siphon/files/pg_hba.conf" "== deploy/postgres/pg_hba.conf"
else
    printf "  MISS %-55s %s\n" "deploy/helm/siphon/files/pg_hba.conf" "differs from deploy/postgres/pg_hba.conf"
    fail=$((fail + 1))
fi

# ---------------------------------------------------------------------------
# siphon-core, siphon-launcher, siphon-mail, siphon-auth: standalone — no
# downstream artifacts to check. Their versions live only in their own
# Cargo.toml.
# ---------------------------------------------------------------------------
core_ver="$(cargo_version crates/siphon-core/Cargo.toml)"
launcher_ver="$(cargo_version crates/siphon-launcher/Cargo.toml)"
auth_ver="$(cargo_version crates/siphon-auth/Cargo.toml)"
echo "siphon-core ${core_ver} (standalone)"
echo "siphon-launcher ${launcher_ver} (standalone)"
echo "siphon-auth ${auth_ver} (standalone)"

# ---------------------------------------------------------------------------
# Cargo.lock agrees with the manifests it locks
# ---------------------------------------------------------------------------
# The gap that let main carry a stale lockfile. Nothing compared the
# lockfile's workspace members against the crates' own Cargo.toml, so
# siphon-auth sat at 0.1.0 in Cargo.lock while its manifest said 0.1.1, and
# siphon-launcher at 2.1.2 against a manifest saying 2.1.4.
#
# Neither existing gate could see it. The checks above compare manifests
# against Dockerfiles, Helm values and compose, and never read Cargo.lock;
# generate-sbom.sh --check compares the SBOMs against Cargo.lock, and those
# agreed, because both were stale together. The SBOMs then published
# pkg:cargo/siphon-auth@0.1.0 for a crate that had not been 0.1.0 for some
# time — in the one artifact whose whole job is saying what shipped.
#
# `cargo check` or any other resolve fixes this silently, which is why it
# survived: the drift only exists in the committed file, and the first local
# build repairs the working tree without telling anyone.
echo
echo "Cargo.lock vs manifests"
for manifest in Cargo.toml crates/*/Cargo.toml; do
    [[ -f "${manifest}" ]] || continue
    pkg_name="$(cargo_name "${manifest}")"
    [[ -n "${pkg_name}" ]] || continue
    manifest_ver="$(cargo_version "${manifest}")"
    locked_ver="$(lock_version "${pkg_name}")"
    if [[ -z "${locked_ver}" ]]; then
        # A workspace member absent from Cargo.lock entirely: the lockfile
        # predates the crate. Report it rather than passing on an empty match.
        check "  Cargo.lock ${pkg_name}" "${manifest_ver}" "(absent)"
    else
        check "  Cargo.lock ${pkg_name}" "${manifest_ver}" "${locked_ver}"
    fi
done

# ---------------------------------------------------------------------------
echo
if [[ $fail -ne 0 ]]; then
    echo "Versions drift — run scripts/bump-version.sh <target> <new> to re-sync" >&2
    # Counted, not flagged. This line used to print a boolean, so two drifted
    # files reported "1 miss" — enough to have someone fix one, re-run, and
    # be surprised.
    if [[ "${fail}" -eq 1 ]]; then
        echo "the affected crate's downstream artifacts. ${checks} checks, 1 miss." >&2
    else
        echo "the affected crate's downstream artifacts. ${checks} checks, ${fail} misses." >&2
    fi
    exit 1
fi
echo "all ${checks} lockstep checks in sync ✓"
