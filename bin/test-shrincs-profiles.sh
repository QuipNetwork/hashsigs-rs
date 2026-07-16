#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> cargo test (default shrincs-256s-keccak)"
cargo test

echo "==> cargo test --features profile-256s-sha2"
cargo test --features profile-256s-sha2

echo "==> cargo test --features profile-128s-q18"
cargo test --features profile-128s-q18

echo "==> cargo test --features profile-128s-q20"
cargo test --features profile-128s-q20
