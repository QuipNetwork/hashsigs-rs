#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> cargo test (default shrincs-256s-keccak)"
cargo test

echo "==> cargo test --features profile-256s-sha2"
cargo test --features profile-256s-sha2

# The 128s profiles run in release. Their unignored tests build a 2^18-leaf
# hypertree with FORS trees of height 24; a debug build makes that slow enough
# to look like a hang (observed: >25min without completing a single test, vs
# ~8min for the whole release suite).
echo "==> cargo test --release --features profile-128s-q18"
cargo test --release --features profile-128s-q18

echo "==> cargo test --release --features profile-128s-q20"
cargo test --release --features profile-128s-q20
