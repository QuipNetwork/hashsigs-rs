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

crate_version="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
  "${REPO_ROOT}/Cargo.toml")"

bash "${REPO_ROOT}/bin/sync-versions.sh" check "${REPO_ROOT}" >/dev/null ||
  fail "the real tree should already be in sync"

fixture="$(mktemp -d)"
missing_root="$(mktemp -d)"
unparseable="$(mktemp -d)"
two_versions="$(mktemp -d)"
py_mismatch="$(mktemp -d)"
trap 'rm -rf "${fixture}" "${missing_root}" "${unparseable}" "${two_versions}" "${py_mismatch}"' EXIT

mkdir -p "${fixture}/ts"
printf 'version = "9.9.9"\n' >"${fixture}/Cargo.toml"
printf '{"version":"0.0.1"}\n' >"${fixture}/ts/package.json"

if bash "${REPO_ROOT}/bin/sync-versions.sh" check "${fixture}" >/dev/null 2>&1; then
  fail "a mismatched tree should exit non-zero"
fi

# A drifted py/Cargo.toml must fail even when root and ts agree: maturin reads
# the PyPI wheel version from that manifest, so it is release-gating.
mkdir -p "${py_mismatch}/ts" "${py_mismatch}/py"
printf 'version = "9.9.9"\n' >"${py_mismatch}/Cargo.toml"
printf '{"version":"9.9.9"}\n' >"${py_mismatch}/ts/package.json"
printf 'version = "0.0.1"\n' >"${py_mismatch}/py/Cargo.toml"
status=0
stderr="$(bash "${REPO_ROOT}/bin/sync-versions.sh" check "${py_mismatch}" 2>&1 1>/dev/null)" ||
  status=$?
[[ "${status}" -eq 1 ]] || fail "a drifted py/Cargo.toml should exit 1, got ${status}"
[[ "${stderr}" == *"py/Cargo.toml"* ]] ||
  fail "a drifted py/Cargo.toml should be named in the error, got: ${stderr}"

status=0
stderr="$(bash "${REPO_ROOT}/bin/sync-versions.sh" check "${missing_root}" 2>&1 1>/dev/null)" ||
  status=$?
[[ "${status}" -eq 1 ]] || fail "a missing Cargo.toml should exit 1, got ${status}"
[[ "${stderr}" == *"could not read version from"* ]] ||
  fail "a missing Cargo.toml should report 'could not read version from', got: ${stderr}"

mkdir -p "${unparseable}/ts"
printf 'version = "1.2.3"\n' >"${unparseable}/Cargo.toml"
printf '{ not json\n' >"${unparseable}/ts/package.json"
status=0
stderr="$(bash "${REPO_ROOT}/bin/sync-versions.sh" check "${unparseable}" 2>&1 1>/dev/null)" ||
  status=$?
[[ "${status}" -eq 1 ]] || fail "an unparseable package.json should exit 1, got ${status}"
[[ "${stderr}" == *"could not read a version from"* ]] ||
  fail "an unparseable package.json should report 'could not read a version from', got: ${stderr}"

printf 'version = "1.2.3"\nversion = "4.5.6"\n' >"${two_versions}/Cargo.toml"
status=0
stderr="$(bash "${REPO_ROOT}/bin/sync-versions.sh" check "${two_versions}" 2>&1 1>/dev/null)" ||
  status=$?
[[ "${status}" -eq 1 ]] || fail "two version lines should exit 1, got ${status}"
[[ "${stderr}" == *"expected exactly one version line"* ]] ||
  fail "two version lines should report 'expected exactly one version line', got: ${stderr}"

# expect: agrees with the real tree.
combined="$(bash "${REPO_ROOT}/bin/sync-versions.sh" expect "${crate_version}" "${REPO_ROOT}" 2>&1)" ||
  fail "expect with the correct version should exit 0, got: ${combined}"
[[ "${combined}" == *"version check OK"* ]] ||
  fail "expect with the correct version should print 'version check OK', got: ${combined}"
[[ "${combined}" != *"set every manifest"* ]] ||
  fail "a successful expect must not print the remediation line, got: ${combined}"

# expect: disagrees with the real tree.
status=0
stderr="$(bash "${REPO_ROOT}/bin/sync-versions.sh" expect "9.9.9-definitely-wrong" "${REPO_ROOT}" \
  2>&1 1>/dev/null)" || status=$?
[[ "${status}" -eq 1 ]] || fail "expect with a wrong version should exit 1, got ${status}"
[[ "${stderr}" == *'expected "9.9.9-definitely-wrong"'* ]] ||
  fail "expect with a wrong version should quote the expected version, got: ${stderr}"
[[ "${stderr}" == *"set every manifest and the release tag to the same version, then re-run"* ]] ||
  fail "expect with a wrong version should print the remediation line, got: ${stderr}"

# expect: no VERSION given is a usage error, not a check failure.
status=0
stderr="$(bash "${REPO_ROOT}/bin/sync-versions.sh" expect 2>&1 1>/dev/null)" || status=$?
[[ "${status}" -eq 2 ]] || fail "expect with no VERSION should exit 2, got ${status}"
[[ "${stderr}" == *"usage:"* ]] ||
  fail "expect with no VERSION should print the usage line, got: ${stderr}"

echo "sync-versions invariants OK"
