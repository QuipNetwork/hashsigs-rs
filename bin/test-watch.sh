#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
Usage: ./bin/test-watch.sh [--profile <profile>] <area> [poll-seconds] [extra args...]
       ./bin/test-watch.sh help

Examples:
  ./bin/test-watch.sh signer-stateful
  ./bin/test-watch.sh --profile 256s-sha2 signer-stateful
  ./bin/test-watch.sh signer-exact 1 generated_stateful_signature_verifies
  ./bin/test-watch.sh account-exact 1 full_rotation_with_replaced_stateless_key_resets_usage
  ./bin/test-watch.sh wasm-compile 2
  ./bin/test-watch.sh account 1 -- --nocapture

This watches source/test/build files and reruns ./bin/test-fast.sh <area>
whenever something changes.
EOF
  printf '\nAvailable areas from test-fast.sh:\n\n'
  ./bin/test-fast.sh --help
}

if [ "${1:-}" = "" ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] || [ "${1:-}" = "help" ]; then
  usage
  exit 0
fi

profile_args=()
if [ "${1:-}" = "--profile" ]; then
  if [ "${2:-}" = "" ]; then
    echo "error: --profile requires a value" >&2
    usage >&2
    exit 1
  fi
  profile_args=(--profile "$2")
  shift 2
fi

area="$1"
shift

poll_secs="1"
if [ "${1:-}" != "" ] && [[ "${1:-}" =~ ^[0-9]+$ ]]; then
  poll_secs="$1"
  shift
fi

watch_fingerprint() {
  find src tests bin solana -type f 2>/dev/null \
    \( -name '*.rs' -o -name '*.toml' -o -name '*.sh' -o -name '*.json' -o -name '*.mjs' -o -name '*.ts' \) \
    -printf '%p %T@ %s\n'
  find . -maxdepth 1 -type f 2>/dev/null \
    \( -name 'Cargo.toml' -o -name 'Cargo.lock' -o -name 'build.rs' -o -name 'README.md' -o -name 'rust-toolchain.toml' \) \
    -printf '%p %T@ %s\n'
}

run_once() {
  local start_ts end_ts duration
  start_ts="$(date +%s)"
  printf '\n==> %s | %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "./bin/test-fast.sh ${profile_args[*]} $area $*"
  ./bin/test-fast.sh "${profile_args[@]}" "$area" "$@"
  end_ts="$(date +%s)"
  duration="$((end_ts - start_ts))"
  printf '\n'
  printf '%s\n' '----------------------------------------'
  printf '==> %s | run duration: %ss\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$duration"
  printf '==> %s | run finished; waiting for changes\n' "$(date '+%Y-%m-%d %H:%M:%S')"
  printf '%s\n' '----------------------------------------'
  printf '\n'
}

last_fingerprint="$(watch_fingerprint)"
run_once "$@"

while true; do
  sleep "$poll_secs"
  current_fingerprint="$(watch_fingerprint)"
  if [ "$current_fingerprint" != "$last_fingerprint" ]; then
    last_fingerprint="$current_fingerprint"
    run_once "$@"
  fi
done
