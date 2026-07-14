#!/usr/bin/env bash

set -euo pipefail

TARGET="${1:-bundler}"
OUT_BASE="${2:-pkg}"

case "$TARGET" in
  bundler|web|nodejs)
    ;;
  *)
    echo "unsupported wasm-pack target: $TARGET" >&2
    echo "expected one of: bundler, web, nodejs" >&2
    exit 1
    ;;
esac

OUT_DIR="$OUT_BASE/$TARGET"

wasm-pack build \
  --release \
  --target "$TARGET" \
  --out-dir "$OUT_DIR" \
  --features wasm-bindings

echo "built WASM package in $OUT_DIR"
