#!/usr/bin/env bash

# Copyright (C) 2026 quip.network
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

# Check that every manifest carries the root Cargo.toml version.
#
# The root Cargo.toml is the single source. This script never rewrites a
# manifest: it fails the build when two disagree, so a release cannot ship a
# mismatched version. Replaces ts/scripts/sync-version.mjs, which checked
# only the npm manifest.
#
# usage: bin/sync-versions.sh check [ROOT]
#        bin/sync-versions.sh expect VERSION [ROOT]
#
# `check` verifies every other manifest against Cargo.toml. `expect` does that
# AND asserts Cargo.toml itself equals a version the caller names, which is how
# CI checks a git tag. Both modes live here so nothing else in the tree needs
# its own idea of how to read a version out of a manifest.

mode="${1:-}"
default_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "${mode}" in
check)
  expected=""
  root="${2:-${default_root}}"
  ;;
expect)
  expected="${2:-}"
  root="${3:-${default_root}}"
  if [[ -z "${expected}" ]]; then
    echo "usage: $0 expect VERSION [ROOT]" >&2
    exit 2
  fi
  ;;
*)
  echo "usage: $0 check [ROOT] | expect VERSION [ROOT]" >&2
  exit 2
  ;;
esac

# `|| true` and the redirect are load-bearing: under `set -e` with
# `pipefail`, a missing Cargo.toml makes sed exit 2 and kills the script
# right here, so the guards below could never run and the caller would see a
# raw sed error under the usage exit code.
version_lines="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
  "${root}/Cargo.toml" 2>/dev/null || true)"

if [[ -z "${version_lines}" ]]; then
  echo "could not read version from ${root}/Cargo.toml" >&2
  exit 1
fi

# Do not take the first match and hope. A second unindented `version =` line
# means another table declares one too, and this script exists so that no
# release ships a version nobody chose.
if [[ "$(wc -l <<<"${version_lines}")" -ne 1 ]]; then
  echo "expected exactly one version line in ${root}/Cargo.toml, found:" >&2
  echo "${version_lines}" >&2
  exit 1
fi

crate_version="${version_lines}"

status=0

check_json() {
  local path="$1"
  [[ -f "${path}" ]] || return 0
  local found
  # Same reason as the sed above: an unparseable manifest must produce an
  # actionable line, not a raw Node stack trace under `set -e`.
  if ! found="$(node -e 'process.stdout.write(require(process.argv[1]).version || "")' \
    "${path}" 2>/dev/null)"; then
    echo "could not read a version from ${path}" >&2
    status=1
    return 0
  fi
  if [[ "${found}" != "${crate_version}" ]]; then
    echo "version mismatch: ${path} is \"${found}\", Cargo.toml is \"${crate_version}\"" >&2
    status=1
  fi
}

check_toml() {
  local path="$1"
  [[ -f "${path}" ]] || return 0
  local lines
  # Same guards as the root read above: fail with an actionable line on a
  # missing/unreadable manifest, and refuse a manifest with two top-level
  # version lines rather than trusting the first.
  lines="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
    "${path}" 2>/dev/null || true)"
  if [[ -z "${lines}" ]]; then
    echo "could not read a version from ${path}" >&2
    status=1
    return 0
  fi
  if [[ "$(wc -l <<<"${lines}")" -ne 1 ]]; then
    echo "expected exactly one version line in ${path}, found:" >&2
    echo "${lines}" >&2
    status=1
    return 0
  fi
  if [[ "${lines}" != "${crate_version}" ]]; then
    echo "version mismatch: ${path} is \"${lines}\", Cargo.toml is \"${crate_version}\"" >&2
    status=1
  fi
}

check_json "${root}/ts/package.json"
# maturin derives the PyPI wheel version from py/Cargo.toml (py/pyproject.toml
# declares `dynamic = ["version"]`), so the PyPI artifact is gated here exactly
# like the npm one. Both sides are Cargo-format strings; maturin performs the
# PEP 440 conversion (0.2.1-rc3 -> 0.2.1rc3) at build time.
check_toml "${root}/py/Cargo.toml"

# The per-profile extension crates and the shared PyO3 layer all ship inside
# that one wheel, so a version drifting here would put mismatched extensions
# next to each other in a single artifact. `version()` is exported from every
# extension and the Python suite asserts they agree, but this catches it before
# anything is built.
check_toml "${root}/py/common/Cargo.toml"
for manifest in "${root}"/py/profiles/*/Cargo.toml; do
  check_toml "${manifest}"
done

# The caller named a version, so Cargo.toml gets checked too instead of being
# taken as the truth everything else is measured against.
if [[ -n "${expected}" && "${expected}" != "${crate_version}" ]]; then
  echo "version mismatch: expected \"${expected}\", Cargo.toml is \"${crate_version}\"" >&2
  status=1
fi

if [[ "${status}" -eq 0 ]]; then
  echo "version check OK: every manifest is at ${crate_version}"
else
  echo "set every manifest and the release tag to the same version, then re-run" >&2
fi

exit "${status}"
