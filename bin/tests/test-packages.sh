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

# Invariant test for bin/packages.sh. A profile with no sibling package is a
# profile that never gets built, and nothing else in the tree would say so.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=packages.sh
source "${SCRIPT_DIR}/packages.sh"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

[[ -n "${DEFAULT_PROFILE}" ]] || fail "DEFAULT_PROFILE is empty"
[[ ${#SIBLING_PROFILES[@]} -eq 3 ]] ||
  fail "expected 3 sibling profiles, got ${#SIBLING_PROFILES[@]}"
[[ ${#PYPI_SIBLINGS[@]} -eq ${#SIBLING_PROFILES[@]} ]] ||
  fail "PYPI_SIBLINGS (${#PYPI_SIBLINGS[@]}) does not match SIBLING_PROFILES (${#SIBLING_PROFILES[@]})"
[[ ${#NPM_SIBLINGS[@]} -eq ${#SIBLING_PROFILES[@]} ]] ||
  fail "NPM_SIBLINGS (${#NPM_SIBLINGS[@]}) does not match SIBLING_PROFILES (${#SIBLING_PROFILES[@]})"
[[ ${#TRIPLES[@]} -eq 6 ]] || fail "expected 6 target triples, got ${#TRIPLES[@]}"

# Equal lengths are not enough. Every later script zips these arrays by
# index, so entry i of each must describe SIBLING_PROFILES[i]. Reordering
# one array and not the other keeps the counts correct and ships the wrong
# package name under a profile's feature flags.
for i in "${!SIBLING_PROFILES[@]}"; do
  sibling_profile="${SIBLING_PROFILES[${i}]}"
  [[ "${PYPI_SIBLINGS[${i}]}" == "hashsigs-profile-${sibling_profile}" ]] ||
    fail "PYPI_SIBLINGS[${i}] is ${PYPI_SIBLINGS[${i}]}, expected hashsigs-profile-${sibling_profile}"
  [[ "${NPM_SIBLINGS[${i}]}" == "${NPM_BASE}-${sibling_profile}" ]] ||
    fail "NPM_SIBLINGS[${i}] is ${NPM_SIBLINGS[${i}]}, expected ${NPM_BASE}-${sibling_profile}"
done

for profile in "${DEFAULT_PROFILE}" "${SIBLING_PROFILES[@]}"; do
  feature="$(PROFILE_FEATURE "${profile}")"
  [[ -n "${feature}" ]] || fail "no cargo feature mapped for profile ${profile}"
  grep -q "^${feature} = " "${SCRIPT_DIR}/../Cargo.toml" ||
    fail "cargo feature ${feature} (profile ${profile}) is not declared in Cargo.toml"
done

echo "packages.sh invariants OK"
