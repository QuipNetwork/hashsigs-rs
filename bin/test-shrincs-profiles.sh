#!/usr/bin/env bash

# Manual / scheduled mirror of the CI profile matrix (see .gitlab-ci.yml):
# - build-test: default 256s-keccak + profile-256s-sha2 (debug/test profile)
# - test-128s:  profile-128s-q18 + profile-128s-q20 (release, full suite), and
#               their sha2 twins (release, --lib only), plus a compile-only
#               check of all test targets for the sha2 twins
# Keep --locked flags and profile feature names aligned with those jobs.
#
# By default the script mirrors CI. The 128s tests that run a full key
# generation or a stateless signature are marked ignored under the 128s
# profiles, so CI skips them. To run them locally as well, set
# INCLUDE_IGNORED_128S=1 (they take tens of minutes):
#
#   INCLUDE_IGNORED_128S=1 bin/test-shrincs-profiles.sh

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
echo "==> cargo test --locked --release --features profile-128s-q18"
cargo test --locked --release --features profile-128s-q18

echo "==> cargo test --locked --release --features profile-128s-q20"
cargo test --locked --release --features profile-128s-q20

# The sha2 twins run the library suite only, as CI does: their integration
# tests pin bytes against account-wrapper vectors that do not exist for these
# two profiles yet. Raise --lib to a full `cargo test` once
# tests/test_vectors/shrincs_account_wrapper_vectors_128s_q{18,20}_sha2.json.gz
# exist. --all-targets is still checked so the integration tests keep compiling.
for feature in profile-128s-q18-sha2 profile-128s-q20-sha2; do
  echo "==> cargo test --locked --release --lib --features ${feature}"
  cargo test --locked --release --lib --features "${feature}"
done

for feature in profile-128s-q18-sha2 profile-128s-q20-sha2; do
  echo "==> cargo check --locked --release --all-targets --features ${feature}"
  cargo check --locked --release --all-targets --features "${feature}"
done

# Opt-in local pass: run only the tests that CI skips under the 128s
# profiles (key generation and stateless signing). Off by default.
if [[ "${INCLUDE_IGNORED_128S:-0}" == "1" ]]; then
  for feature in profile-128s-q18 profile-128s-q20 profile-128s-q18-sha2 profile-128s-q20-sha2; do
    echo "==> cargo test --locked --release --lib --features ${feature} -- --ignored (local only)"
    cargo test --locked --release --lib --features "${feature}" -- --ignored
  done
fi
