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

# One distribution per ecosystem carries every profile.
#
# Each ecosystem publishes exactly one artifact: one crate, one PyPI
# distribution, one npm package. Every profile ships inside it and is imported
# on its own path, so a caller takes the profile it wants without taking a
# second dependency:
#
#   Rust    use hashsigs_rs::profiles::p128s_q18::Shrincs;
#   Python  from hashsigs.profiles import p128s_q18
#   npm     import { shrincs } from "@quip.network/hashsigs-wasm/128s-q18"
#
# This replaces an earlier sibling-package model, where each opt-in profile was
# its own distribution pinning the base. Sibling packages multiply the release
# surface by the profile count, and they let a caller install a profile package
# whose version has drifted from the base it pins. One distribution cannot
# drift from itself.

# The profile the non-generic surfaces bind to: the wasm bindings, the
# `ShrincsVerifier` facade, and the golden-vector generator. It is the profile
# a caller gets from a bare import, not the only profile in the artifact.
DEFAULT_PROFILE="256s-keccak"

# Every profile the published artifacts carry, default included.
PROFILES=(256s-keccak 256s-sha2 128s-q18 128s-q20 128s-q18-sha2 128s-q20-sha2)

# Map a profile name to the cargo feature that compiles AND selects it.
#
# `cargo build --features "$(PROFILE_FEATURE 128s-q18)"` is enough: default
# features may stay on. Cargo features are additive, so the default profile
# remains enabled, but it is enabled through the `default-profile-256s` marker,
# and build.rs lets any single explicitly named profile override that marker.
# Adding --no-default-features is therefore unnecessary here, and would also
# drop `std`. Verify with:
#   cargo check --features <feature> -v | grep -o -- '--cfg shrincs_default_profile_[a-z0-9_]*'
#
# Selection matters only for the non-generic surfaces above. Building the
# artifact that carries every profile enables them all at once.
PROFILE_FEATURE() {
  case "$1" in
  256s-keccak) echo "profile-256s" ;;
  256s-sha2) echo "profile-256s-sha2" ;;
  128s-q18) echo "profile-128s-q18" ;;
  128s-q20) echo "profile-128s-q20" ;;
  128s-q18-sha2) echo "profile-128s-q18-sha2" ;;
  128s-q20-sha2) echo "profile-128s-q20-sha2" ;;
  *)
    echo "unknown profile: $1" >&2
    return 1
    ;;
  esac
}

# Map a profile to the SHRINCS profile name its binaries report, the value
# `<P as Profile>::PROFILE_NAME` carries and `PROFILE_ID = keccak256(name)`
# hashes. The relation to the key above is irregular -- the 128s keccak
# profiles spell `-keccak` in their name but not in their key, while the 256s
# ones spell it in both -- so it is a table, not a rule.
#
# This restates a constant that lives in `src/profiles/p*.rs`, so it can drift.
# It is checked rather than trusted: the npm conformance suite loads each
# published binary and asserts `profileName()` equals the value below, which
# fails the build both when this table is wrong and when a profile's wasm is
# built into another profile's subpath.
PROFILE_SHRINCS_NAME() {
  case "$1" in
  256s-keccak) echo "shrincs-256s-keccak" ;;
  256s-sha2) echo "shrincs-256s-sha2" ;;
  128s-q18) echo "shrincs-128s-q18-keccak" ;;
  128s-q20) echo "shrincs-128s-q20-keccak" ;;
  128s-q18-sha2) echo "shrincs-128s-q18-sha2" ;;
  128s-q20-sha2) echo "shrincs-128s-q20-sha2" ;;
  *)
    echo "unknown profile: $1" >&2
    return 1
    ;;
  esac
}

# The import path each ecosystem exposes for a profile. Used by the packaging
# checks so a profile cannot ship without a way to reach it.
PROFILE_RUST_MODULE() {
  local p="${1//-/_}"
  case "$1" in
  256s-keccak) echo "hashsigs_rs::profiles::p256s" ;;
  *) echo "hashsigs_rs::profiles::p${p%_keccak}" ;;
  esac
}

# crates.io. One publishable crate; the binding crates carry publish = false.
CRATE=hashsigs-rs

# PyPI. One distribution, every profile inside it.
PYPI_BASE=hashsigs

# npm. One package, every profile inside it, each on its own subpath export.
NPM_BASE="@quip.network/hashsigs-wasm"

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
