#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
Usage: ./bin/test-fast.sh [--profile <profile>] <area> [extra cargo args...]

Fast local-loop test entrypoints:
  lib                   cargo test --lib
  lib-exact <name>      cargo test <name> -- --exact
  compile-default       cargo test --no-run
  signer                cargo test shrincs::signers::shrincs_signer
  signer-stateful       cargo test generated_stateful_signature_verifies -- --exact
  signer-import         cargo test import_ -- --nocapture
  signer-import-exact <name>
                        cargo test <name> -- --exact
  signer-boundary       cargo test stateful_boundary_leaves_and_empty_message_round_trip -- --exact
  signer-stateless      cargo test generated_stateless_raw_signature_verifies -- --exact
  signer-exact <name>   cargo test <name> -- --exact
  account               cargo test account::
  account-rotation      cargo test rotation -- --nocapture
  account-policy        cargo test policy -- --nocapture
  account-exact <name>  cargo test <name> -- --exact
  vectors               cargo test --test test_vectors
  vectors-shrincs       cargo test --test test_vectors solidity_exported_
  vectors-exact <name>  cargo test --test test_vectors <name> -- --exact
  solidity              cargo test --test solidity_account_vectors
  solidity-exact <name> cargo test --test solidity_account_vectors <name> -- --exact
  wasm                  cargo test wasm:: -- --nocapture
  wasm-exact <name>     cargo test <name> -- --exact
  wasm-compile          cargo test --features wasm-bindings --target wasm32-unknown-unknown --no-run
  wasm-node             wasm-pack test --node --features wasm-bindings
  sha2-compile          cargo test --no-run --features profile-256s-sha2
  q18-compile           cargo test --no-run --features profile-128s-q18
  q20-compile           cargo test --no-run --features profile-128s-q20
  full                  cargo test

Profiles:
  default               use the default Cargo profile feature set
  256s-sha2             use --no-default-features --features profile-256s-sha2
  128s-q18              use --no-default-features --features profile-128s-q18
  128s-q20              use --no-default-features --features profile-128s-q20

Examples:
  ./bin/test-fast.sh signer-stateful
  ./bin/test-fast.sh --profile 256s-sha2 signer-stateful
  ./bin/test-fast.sh signer-exact generated_stateful_signature_verifies
  ./bin/test-fast.sh account-exact full_rotation_with_replaced_stateless_key_resets_usage
  ./bin/test-fast.sh vectors-exact solidity_exported_stateful_action_vector_verifies_in_rust
  ./bin/test-fast.sh account-policy
  ./bin/test-fast.sh wasm-compile
EOF
}

if [ "${1:-}" = "" ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

profile="default"
if [ "${1:-}" = "--profile" ]; then
  if [ "${2:-}" = "" ]; then
    echo "error: --profile requires a value" >&2
    usage >&2
    exit 1
  fi
  profile="$2"
  shift 2
fi

area="$1"
shift

case "$profile" in
  default)
    profile_args=()
    ;;
  256s-sha2)
    profile_args=(--no-default-features --features profile-256s-sha2)
    ;;
  128s-q18)
    profile_args=(--no-default-features --features profile-128s-q18)
    ;;
  128s-q20)
    profile_args=(--no-default-features --features profile-128s-q20)
    ;;
  *)
    echo "error: unknown profile '$profile'" >&2
    usage >&2
    exit 1
    ;;
esac

cargo_test() {
  cargo test "${profile_args[@]}" "$@"
}

case "$area" in
  lib)
    cargo_test --lib "$@"
    ;;
  lib-exact)
    if [ "${1:-}" = "" ]; then
      echo "error: lib-exact requires a test name" >&2
      usage >&2
      exit 1
    fi
    test_name="$1"
    shift
    cargo_test "$test_name" -- --exact "$@"
    ;;
  compile-default)
    cargo_test --no-run "$@"
    ;;
  signer)
    cargo_test shrincs::signers::shrincs_signer "$@"
    ;;
  signer-stateful)
    cargo_test generated_stateful_signature_verifies -- --exact "$@"
    ;;
  signer-import)
    cargo_test import_ -- --nocapture "$@"
    ;;
  signer-import-exact)
    if [ "${1:-}" = "" ]; then
      echo "error: signer-import-exact requires a test name" >&2
      usage >&2
      exit 1
    fi
    test_name="$1"
    shift
    cargo_test "$test_name" -- --exact "$@"
    ;;
  signer-boundary)
    cargo_test stateful_boundary_leaves_and_empty_message_round_trip -- --exact "$@"
    ;;
  signer-stateless)
    cargo_test generated_stateless_raw_signature_verifies -- --exact "$@"
    ;;
  signer-exact)
    if [ "${1:-}" = "" ]; then
      echo "error: signer-exact requires a test name" >&2
      usage >&2
      exit 1
    fi
    test_name="$1"
    shift
    cargo_test "$test_name" -- --exact "$@"
    ;;
  account)
    cargo_test account:: "$@"
    ;;
  account-rotation)
    cargo_test rotation -- --nocapture "$@"
    ;;
  account-policy)
    cargo_test policy -- --nocapture "$@"
    ;;
  account-exact)
    if [ "${1:-}" = "" ]; then
      echo "error: account-exact requires a test name" >&2
      usage >&2
      exit 1
    fi
    test_name="$1"
    shift
    cargo_test "$test_name" -- --exact "$@"
    ;;
  vectors)
    cargo_test --test test_vectors "$@"
    ;;
  vectors-shrincs)
    cargo_test --test test_vectors solidity_exported_ "$@"
    ;;
  vectors-exact)
    if [ "${1:-}" = "" ]; then
      echo "error: vectors-exact requires a test name" >&2
      usage >&2
      exit 1
    fi
    test_name="$1"
    shift
    cargo_test --test test_vectors "$test_name" -- --exact "$@"
    ;;
  solidity)
    cargo_test --test solidity_account_vectors "$@"
    ;;
  solidity-exact)
    if [ "${1:-}" = "" ]; then
      echo "error: solidity-exact requires a test name" >&2
      usage >&2
      exit 1
    fi
    test_name="$1"
    shift
    cargo_test --test solidity_account_vectors "$test_name" -- --exact "$@"
    ;;
  wasm)
    cargo_test wasm:: -- --nocapture "$@"
    ;;
  wasm-exact)
    if [ "${1:-}" = "" ]; then
      echo "error: wasm-exact requires a test name" >&2
      usage >&2
      exit 1
    fi
    test_name="$1"
    shift
    cargo_test "$test_name" -- --exact "$@"
    ;;
  wasm-compile)
    cargo_test --features wasm-bindings --target wasm32-unknown-unknown --no-run "$@"
    ;;
  wasm-node)
    if [ "$profile" != "default" ]; then
      echo "error: wasm-node currently supports only the default profile" >&2
      exit 1
    fi
    wasm-pack test --node --features wasm-bindings "$@"
    ;;
  sha2-compile)
    cargo test --no-run --no-default-features --features profile-256s-sha2 "$@"
    ;;
  q18-compile)
    cargo test --no-run --no-default-features --features profile-128s-q18 "$@"
    ;;
  q20-compile)
    cargo test --no-run --no-default-features --features profile-128s-q20 "$@"
    ;;
  full)
    cargo_test "$@"
    ;;
  *)
    echo "error: unknown area '$area'" >&2
    usage >&2
    exit 1
    ;;
esac
