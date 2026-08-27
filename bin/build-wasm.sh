#!/usr/bin/env bash

# Build the SHRINCS wasm from the audited Rust crate and emit wasm-bindgen
# bindings for both the Node.js and web targets, once per published profile.
#
# We use the two-step `cargo build` + `wasm-bindgen` CLI flow rather than
# `wasm-pack`: recent Cargo (>=1.93) moved `build --out-dir` behind the
# nightly-only `--artifact-dir`, which breaks `wasm-pack build`. The two-step
# flow does the exact same work without the broken flag.
#
# Prereqs:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version 0.2.100   # must equal the crate's wasm-bindgen version
#
# Profile scope: one binary per profile, each under
# `$OUT/profiles/<profile>/{nodejs,web}`, and one npm subpath export per
# profile on top of them. A binary carries exactly one profile because the
# `#[wasm_bindgen]` export names are not profile-prefixed; see
# `src/wasm/export.rs`. Six binaries rather than one fat binary because the
# browser build inlines the wasm as base64, where no bundler can drop the
# profiles a caller never imported. A shipped profile binary is 133-147 KB,
# which is 178-196 KB once base64 encoded.

set -euo pipefail

# Where the generated bindings land. CI and the ts/ package expect ts/src.
OUT="${1:-ts/src}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

# The published profile set and the profile->feature mapping. Sourcing this is
# what keeps the wasm build, the packaging checks, and the crate's own feature
# list from holding three different ideas of "every profile".
# shellcheck source-path=SCRIPTDIR
# shellcheck source=packages.sh
source "${SCRIPT_DIR}/packages.sh"

WASM="target/wasm32-unknown-unknown/release/hashsigs_rs.wasm"

# Must equal the crate's pinned wasm-bindgen version (Cargo.toml); a mismatched
# CLI produces a cryptic schema error at build or runtime.
REQUIRED_WB="0.2.100"

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "error: wasm-bindgen CLI not found. Install with:" >&2
  echo "  cargo install wasm-bindgen-cli --version $REQUIRED_WB" >&2
  exit 1
fi

HAVE_WB="$(wasm-bindgen --version | awk '{print $2}')"
if [ "$HAVE_WB" != "$REQUIRED_WB" ]; then
  echo "error: wasm-bindgen CLI is $HAVE_WB but $REQUIRED_WB is required" >&2
  echo "       (a version mismatch produces a wasm-bindgen schema error)." >&2
  echo "  cargo install wasm-bindgen-cli --version $REQUIRED_WB --force" >&2
  exit 1
fi

for profile in "${PROFILES[@]}"; do
  feature="$(PROFILE_FEATURE "$profile")"
  dest="$OUT/profiles/$profile"

  echo "building $profile ($feature)"

  # Force a recompile of this crate (deps stay cached). The cdylib output path
  # is shared and un-hashed across crate versions AND across profiles, so an
  # incremental build can declare a previously built artifact "fresh" and ship
  # stale bytes — here that would mean shipping one profile's wasm under
  # another profile's subpath, which no later check would catch.
  cargo clean -p hashsigs-rs --release --target wasm32-unknown-unknown

  # --no-default-features pins exactly one profile into the binary. Leaving the
  # defaults on would also work (build.rs lets an explicitly named profile
  # override the default marker), but "exactly one profile is compiled" is the
  # property this build wants, and asserting it here beats relying on that
  # override staying correct.
  #
  # Cargo.toml ships crate-type = ["rlib"] so host no_std builds work; request
  # cdylib here so wasm-bindgen gets a .wasm artifact.
  cargo rustc --release --target wasm32-unknown-unknown \
    --no-default-features --features "wasm-bindings,std,$feature" \
    --crate-type cdylib --crate-type rlib

  rm -rf "$dest/nodejs" "$dest/web"
  mkdir -p "$dest"
  for target in nodejs web; do
    wasm-bindgen "$WASM" --out-dir "$dest/$target" --target "$target"
  done
done

# The profile list the JS build scripts iterate. Generated rather than
# hand-maintained so `bin/packages.sh` stays the one place a profile is added.
mkdir -p "$OUT/profiles"
{
  printf '{\n  "default": "%s",\n  "profiles": [\n' "$DEFAULT_PROFILE"
  for i in "${!PROFILES[@]}"; do
    sep=","
    [ "$i" -eq $((${#PROFILES[@]} - 1)) ] && sep=""
    printf '    { "key": "%s", "name": "%s" }%s\n' \
      "${PROFILES[$i]}" "$(PROFILE_SHRINCS_NAME "${PROFILES[$i]}")" "$sep"
  done
  printf '  ]\n}\n'
} >"$OUT/profiles/profiles.json"

echo "built ${#PROFILES[@]} profiles (nodejs + web) into $OUT/profiles"
