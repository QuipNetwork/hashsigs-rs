#!/usr/bin/env bash

# Build the SHRINCS wasm from the audited Rust crate and emit wasm-bindgen
# bindings for both the Node.js and web targets.
#
# We use the two-step `cargo build` + `wasm-bindgen` CLI flow rather than
# `wasm-pack`: recent Cargo (>=1.93) moved `build --out-dir` behind the
# nightly-only `--artifact-dir`, which breaks `wasm-pack build`. The two-step
# flow does the exact same work without the broken flag.
#
# Prereqs:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version 0.2.100   # must equal the crate's wasm-bindgen version

set -euo pipefail

# Where the generated bindings land. CI and the ts/ package expect ts/src.
OUT="${1:-ts/src}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WASM="target/wasm32-unknown-unknown/release/hashsigs_rs.wasm"

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "error: wasm-bindgen CLI not found. Install with:" >&2
  echo "  cargo install wasm-bindgen-cli --version 0.2.100" >&2
  exit 1
fi

cargo build --release --target wasm32-unknown-unknown --features wasm-bindings

for target in nodejs web; do
  wasm-bindgen "$WASM" --out-dir "$OUT/$target" --target "$target"
done

echo "built nodejs + web bindings into $OUT"
