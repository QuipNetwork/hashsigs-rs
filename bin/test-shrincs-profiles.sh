#!/usr/bin/env bash

# Manual / scheduled mirror of the CI profile matrix (see .gitlab-ci.yml):
# - build-test: default 256s-keccak + profile-256s-sha2 (debug/test profile)
# - test-128s:  experimental-profile-128s-q18 + experimental-profile-128s-q20 (release), plus a
#               compile-only check of their sha2 twins
# Keep --locked flags and profile feature names aligned with those jobs.

set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> cargo test --locked (default shrincs-256s-keccak)"
cargo test --locked

echo "==> cargo test --locked --features profile-256s-sha2"
cargo test --locked --features profile-256s-sha2

# The 128s profiles run in release. Their unignored tests build a 2^18-leaf
# hypertree with FORS trees of height 24; a debug build makes that slow enough
# to look like a hang (observed: >25min without completing a single test, vs
# ~8min for the whole release suite). CI runs these in the test-128s job.
echo "==> cargo test --locked --release --features experimental-profile-128s-q18"
cargo test --locked --release --features experimental-profile-128s-q18

echo "==> cargo test --locked --release --features experimental-profile-128s-q20"
cargo test --locked --release --features experimental-profile-128s-q20

# The sha2 twins of the two profiles above are compiled, not tested: their
# golden vectors are not generated yet, so the vector-conformance tests would
# fail on a missing file rather than on a real defect. Raise these to
# `cargo test` once tests/test_vectors/shrincs_sphincs_128s_q{18,20}_sha2.json.gz
# exist.
for feature in experimental-profile-128s-q18-sha2 experimental-profile-128s-q20-sha2; do
  echo "==> cargo check --locked --release --all-targets --features ${feature}"
  cargo check --locked --release --all-targets --features "${feature}"
done
