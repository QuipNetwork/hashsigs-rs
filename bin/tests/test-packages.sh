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

# Invariant test for bin/packages.sh. Each ecosystem ships one artifact
# carrying every profile, so the failure this guards is a profile that is
# listed as shipped but has no cargo feature to compile it or no module to
# import it by. Nothing else in the tree would say so.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=packages.sh
source "${SCRIPT_DIR}/packages.sh"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

[[ -n "${DEFAULT_PROFILE}" ]] || fail "DEFAULT_PROFILE is empty"
[[ ${#PROFILES[@]} -eq 6 ]] ||
  fail "expected 6 profiles, got ${#PROFILES[@]}"
[[ ${#TRIPLES[@]} -eq 6 ]] || fail "expected 6 target triples, got ${#TRIPLES[@]}"

# The sibling-package model is gone. Leaving one of its arrays behind would
# leave a publish script iterating a package set that is no longer published.
for stale in SIBLING_PROFILES PYPI_SIBLINGS NPM_SIBLINGS; do
  [[ -z "${!stale+set}" ]] ||
    fail "${stale} still exists; the sibling-package model was replaced by one distribution per ecosystem"
done

# The default profile must be one of the shipped profiles, not a seventh name.
printf '%s\n' "${PROFILES[@]}" | grep -qx "${DEFAULT_PROFILE}" ||
  fail "DEFAULT_PROFILE (${DEFAULT_PROFILE}) is not in PROFILES"

# Every shipped profile needs both halves: a cargo feature that compiles it,
# and a module a caller can import it by. A profile missing either one is
# listed as shipped and is not reachable.
seen_names=()
for profile in "${PROFILES[@]}"; do
  feature="$(PROFILE_FEATURE "${profile}")"
  [[ -n "${feature}" ]] || fail "no cargo feature mapped for profile ${profile}"
  grep -q "^${feature} = " "${SCRIPT_DIR}/../Cargo.toml" ||
    fail "cargo feature ${feature} (profile ${profile}) is not declared in Cargo.toml"

  # The SHRINCS profile name a binary built for this profile reports. Only
  # shape is checked here -- that a name exists, is unique, and is prefixed
  # `shrincs-`. Whether it is the RIGHT name is checked where the answer
  # actually lives: the npm conformance suite loads each built binary and
  # compares `profileName()` against this table.
  shrincs_name="$(PROFILE_SHRINCS_NAME "${profile}")"
  [[ -n "${shrincs_name}" ]] ||
    fail "no SHRINCS profile name mapped for profile ${profile}"
  [[ "${shrincs_name}" == shrincs-* ]] ||
    fail "profile ${profile} maps to SHRINCS name ${shrincs_name}, which is not prefixed 'shrincs-'"
  if printf '%s\n' "${seen_names[@]:-}" | grep -qx "${shrincs_name}"; then
    fail "SHRINCS name ${shrincs_name} is mapped by more than one profile"
  fi
  seen_names+=("${shrincs_name}")

  module="$(PROFILE_RUST_MODULE "${profile}")"
  [[ -n "${module}" ]] || fail "no rust module mapped for profile ${profile}"
  module_file="${SCRIPT_DIR}/../src/profiles/${module##*::}.rs"
  [[ -f "${module_file}" ]] ||
    fail "profile ${profile} maps to ${module}, but ${module_file} does not exist"
done

echo "packages.sh invariants OK"
