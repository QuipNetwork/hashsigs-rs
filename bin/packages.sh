# shellcheck shell=bash
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

# The hashsigs publishable package set.
#
# Sourced by every build, check and publish script so none of them can hold a
# different idea of what "every package" means. Adding a profile is an edit
# here and nowhere else.
#
# Not standalone: source it, do not execute it.

# Names below are read by the sourcing script, never by this file.
# shellcheck disable=SC2034

# The profile that ships in the base package of every ecosystem.
DEFAULT_PROFILE="256s-keccak"

# The opt-in profiles, each published as a sibling package.
SIBLING_PROFILES=(128s-q18 128s-q20 256s-sha2)

# Map a profile name to the cargo feature that compiles AND selects it.
#
# `cargo build --features "$(PROFILE_FEATURE 128s-q18)"` is enough: default
# features may stay on. Cargo features are additive, so the default profile
# remains enabled, but it is enabled through the `default-profile-256s` marker,
# and build.rs lets any single explicitly named profile override that marker.
# Adding --no-default-features is therefore unnecessary here, and would also
# drop `std`. Verify with:
#   cargo check --features <feature> -v | grep -o -- '--cfg shrincs_default_profile_[a-z0-9_]*'
PROFILE_FEATURE() {
  case "$1" in
  256s-keccak) echo "profile-256s" ;;
  128s-q18) echo "profile-128s-q18" ;;
  128s-q20) echo "profile-128s-q20" ;;
  256s-sha2) echo "profile-256s-sha2" ;;
  *)
    echo "unknown profile: $1" >&2
    return 1
    ;;
  esac
}

# crates.io. One publishable crate; the binding crates carry publish = false.
CRATE=hashsigs-rs

# PyPI. The base distribution and one sibling per opt-in profile, in publish
# order: the base must be live before a sibling that pins it.
PYPI_BASE=hashsigs
PYPI_SIBLINGS=(
  hashsigs-profile-128s-q18
  hashsigs-profile-128s-q20
  hashsigs-profile-256s-sha2
)

# npm. Same ordering rule as PyPI.
NPM_BASE="@quip.network/hashsigs-wasm"
NPM_SIBLINGS=(
  "@quip.network/hashsigs-wasm-128s-q18"
  "@quip.network/hashsigs-wasm-128s-q20"
  "@quip.network/hashsigs-wasm-256s-sha2"
)

# Target triples for wheels and C tarballs. Cross-compiled from Linux with
# cargo-zigbuild; the crate has no C dependencies, so no target C toolchain
# is needed.
TRIPLES=(
  x86_64-unknown-linux-gnu
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-gnu
  aarch64-apple-darwin
  x86_64-apple-darwin
  x86_64-pc-windows-msvc
)
