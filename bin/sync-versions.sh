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

mode="${1:-}"
root="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

if [[ "${mode}" != "check" ]]; then
  echo "usage: $0 check [ROOT]" >&2
  exit 2
fi

crate_version="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
  "${root}/Cargo.toml" | head -1)"

if [[ -z "${crate_version}" ]]; then
  echo "could not read version from ${root}/Cargo.toml" >&2
  exit 1
fi

status=0

check_json() {
  local path="$1"
  [[ -f "${path}" ]] || return 0
  local found
  found="$(node -e 'process.stdout.write(require(process.argv[1]).version || "")' \
    "${path}")"
  if [[ "${found}" != "${crate_version}" ]]; then
    echo "version mismatch: ${path} is \"${found}\", Cargo.toml is \"${crate_version}\"" >&2
    status=1
  fi
}

check_json "${root}/ts/package.json"

if [[ "${status}" -eq 0 ]]; then
  echo "version check OK: every manifest is at ${crate_version}"
fi

exit "${status}"
