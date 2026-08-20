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

# bin/sync-versions.sh must pass on this tree and fail on a mismatched one.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

bash "${REPO_ROOT}/bin/sync-versions.sh" check "${REPO_ROOT}" >/dev/null ||
  fail "the real tree should already be in sync"

fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT
mkdir -p "${fixture}/ts"
printf 'version = "9.9.9"\n' >"${fixture}/Cargo.toml"
printf '{"version":"0.0.1"}\n' >"${fixture}/ts/package.json"

if bash "${REPO_ROOT}/bin/sync-versions.sh" check "${fixture}" >/dev/null 2>&1; then
  fail "a mismatched tree should exit non-zero"
fi

echo "sync-versions invariants OK"
