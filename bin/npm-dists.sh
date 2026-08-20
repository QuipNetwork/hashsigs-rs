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

# Build, pack and smoke-test the npm distribution.
#
# `npm pack` validates nothing about the contents. This packs the real
# tarball, installs it into a throwaway project outside the repository, and
# imports it there. An `exports` map that omits a file, or a dist/ that never
# got rebuilt, fails here rather than after publication.
#
# usage: bin/npm-dists.sh check

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=packages.sh
source "${SCRIPT_DIR}/packages.sh"

mode="${1:-}"
if [[ "${mode}" != "check" ]]; then
  echo "usage: $0 check" >&2
  exit 2
fi

scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT

echo "==> packing ${NPM_BASE}"
# prepack runs the full build (wasm, tsc, copy, test), so this exercises the
# same path `npm publish` would. `npm --prefix` does not change which
# directory an implicit "." package spec resolves against, so this runs pack
# from inside ts/ instead. `--silent` suppresses npm's own notices but not
# the build and test output the prepack lifecycle prints to stdout, so the
# tarball filename npm pack reports is only the last line, not the whole
# capture.
pack_output="$(cd "${REPO_ROOT}/ts" && npm pack --silent --pack-destination "${scratch}")"
tarball="$(tail -n1 <<<"${pack_output}")"

echo "==> installing ${tarball} into a throwaway project"
mkdir -p "${scratch}/project"
cd "${scratch}/project"
npm init -y >/dev/null
npm install --silent "${scratch}/${tarball}"

echo "==> importing from outside the repository"
cp "${SCRIPT_DIR}/smoke/npm-smoke.mjs" "${scratch}/project/smoke.mjs"
node "${scratch}/project/smoke.mjs"

echo "npm dists check OK"
