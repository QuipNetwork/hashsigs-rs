#!/usr/bin/env bash

# Build one Python extension per published SHRINCS profile, stage them inside
# the `hashsigs` package, and generate the per-profile Python modules.
#
# The wheel itself is built by maturin afterwards (`maturin build -m
# py/Cargo.toml`), which compiles the small root extension and copies the
# staged package tree verbatim.
#
# Why one extension per profile rather than one carrying all six: it mirrors
# the npm package, and importing a profile maps only that profile's code. The
# cost is real and worth knowing -- each extension statically links its own copy
# of the crate, so the wheel is roughly six times the size of a single-extension
# build. A wheel is downloaded whole, so unlike the browser there is no
# per-import transfer saving to offset it.
#
# One Cargo package builds at most one cdylib, which is why py/profiles/ holds
# six crates rather than one with six targets.
#
# Prereqs:
#   pip install maturin==1.14.1     # only for the wheel step, not this script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

# The published profile set, the profile->feature map, and the profile->SHRINCS
# name table. Sourced so this script cannot hold a different idea of "every
# profile" than the packaging checks and the wasm build.
# shellcheck source-path=SCRIPTDIR
# shellcheck source=packages.sh
source "${SCRIPT_DIR}/packages.sh"

PKG="py/python/hashsigs"
EXT_DIR="${PKG}/_ext"

# Cargo names a cdylib `lib<name>.so`; CPython imports an extension by matching
# the file stem to its init symbol, so each one is renamed on the way in. The
# `.abi3.so` suffix marks it as the stable-ABI build pyo3's abi3-py39 feature
# produces, which one wheel per platform can serve to CPython 3.9 and later.
case "$(uname -s)" in
Darwin) DYLIB_EXT="dylib" ;;
*) DYLIB_EXT="so" ;;
esac

mkdir -p "$EXT_DIR" "${PKG}/profiles"

for profile in "${PROFILES[@]}"; do
  module="$(PROFILE_PYTHON_MODULE "$profile")"
  crate="hashsigs-py-${module//_/-}"
  ext="_hashsigs_${module}"

  echo "building $profile -> $ext"
  cargo build --release -p "$crate"

  built="target/release/lib${ext}.${DYLIB_EXT}"
  [ -f "$built" ] || {
    echo "error: cargo did not produce $built" >&2
    exit 1
  }
  cp "$built" "${EXT_DIR}/${ext}.abi3.so"
done

# The profile list the Python generator reads. Generated rather than
# hand-maintained so bin/packages.sh stays the one place a profile is added.
{
  printf '{\n  "default": "%s",\n  "profiles": [\n' "$DEFAULT_PROFILE"
  for i in "${!PROFILES[@]}"; do
    profile="${PROFILES[$i]}"
    module="$(PROFILE_PYTHON_MODULE "$profile")"
    sep=","
    [ "$i" -eq $((${#PROFILES[@]} - 1)) ] && sep=""
    printf '    { "key": "%s", "name": "%s", "module": "%s", "ext": "_hashsigs_%s" }%s\n' \
      "$profile" "$(PROFILE_SHRINCS_NAME "$profile")" "$module" "$module" "$sep"
  done
  printf '  ]\n}\n'
} >"${PKG}/profiles/profiles.json"

python3 bin/gen-python-profiles.py

echo "built ${#PROFILES[@]} extensions into ${EXT_DIR}"
