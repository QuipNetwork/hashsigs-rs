#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Mutation check: every one-line change to spec/Spec.eca that kat/mutants.tsv
# lists must make the named replay file fail. A mutant that survives shows a
# gap in the vectors. Run after `make kat-gen`.
# Usage: kat/mutation_check.sh [jobs]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
jobs="${1:-4}"
EASYCRYPT="${EASYCRYPT:-easycrypt}"
# A replay that runs longer than this many seconds counts as a failed check.
# Choose a mutant that fails at an early lemma.
LIMIT="${MUTANT_LIMIT:-900}"
work="$(mktemp -d)"
trap 'rm -r -- "$work"' EXIT

run_mutant() {
  local name="$1" group="$2" expression="$3" dir="$work/$1"
  mkdir -p "$dir"
  cp "$root/spec/Search.ec" "$root/spec/Spec.eca" "$root/kat/Compute.ec" \
    "$root/build/kat/ec/Kat_$group.ec" "$dir/"
  sed -i -e "$expression" "$dir/Spec.eca"
  if cmp -s "$root/spec/Spec.eca" "$dir/Spec.eca"; then
    echo "STALE     $name: the expression changes nothing"
    return 1
  fi
  local code=0
  (cd "$dir" && timeout "$LIMIT" "$EASYCRYPT" compile -no-eco "Kat_$group.ec" >/dev/null 2>&1) || code=$?
  if [[ "$code" -eq 0 ]]; then
    echo "SURVIVED  $name: Kat_$group.ec still checks"
    return 1
  elif [[ "$code" -eq 124 ]]; then
    echo "TIMEOUT   $name: Kat_$group.ec ran longer than $LIMIT seconds"
    return 1
  fi
  echo "killed    $name (by $group)"
}

status=0
running=0
while IFS=$'\t' read -r name group expression; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  run_mutant "$name" "$group" "$expression" &
  running=$((running + 1))
  if ((running >= jobs)); then
    wait -n || status=1
    running=$((running - 1))
  fi
done <"$root/kat/mutants.tsv"
while ((running > 0)); do
  wait -n || status=1
  running=$((running - 1))
done
exit "$status"
