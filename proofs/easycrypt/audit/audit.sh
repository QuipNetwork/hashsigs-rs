#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Audit gate. A green proof check does not show these three things:
#   admits   no proof is admitted and no file weakens proof checking
#   axioms   every axiom in scope is on the reviewed allowlist
#   signoff  the reviewed definitions did not change after their sign-off
# The vectors match the Rust code of the crate: `make kat-verify` checks that
# on the host, before `make docker-audit` runs this script.
# Usage: audit/audit.sh [gate ...]   (default: all three gates)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

EASYCRYPT="${EASYCRYPT:-easycrypt}"
SOURCES="${AUDIT_SOURCES:-spec kat build/kat/ec audit/Probe.ec}"
PROBE="${AUDIT_PROBE:-audit/Probe.ec}"
ALLOWLIST="audit/allowlist.txt"
SIGNOFF="${AUDIT_SIGNOFF:-docs/review/SIGNOFF.sha256}"

gate_admits() {
  local hits path existing=()
  for path in $SOURCES; do
    if [[ -e "$path" ]]; then
      existing+=("$path")
    fi
  done
  if [[ "${#existing[@]}" -eq 0 ]]; then
    echo "audit: no source to scan in: $SOURCES" >&2
    return 1
  fi
  hits="$(grep -RnwE --include='*.ec' --include='*.eca' \
    'admit|admitted|Proofs:weak|Proofs:report' "${existing[@]}" || true)"
  if [[ -n "$hits" ]]; then
    printf 'audit: admitted proof or weakened checking:\n%s\n' "$hits" >&2
    return 1
  fi
  echo "audit: admits passed: no admitted proof"
}

gate_axioms() {
  local listing found patterns errors status=0
  errors="$(mktemp)"
  if ! listing="$("$EASYCRYPT" compile -script -no-eco "$PROBE" 2>"$errors")"; then
    cat "$errors" >&2
    rm -- "$errors"
    echo "audit: the probe does not check" >&2
    return 1
  fi
  rm -- "$errors"
  found="$(printf '%s\n' "$listing" | awk '
    /^=+ .* =+$/ { theory = $2 }
    /^axiom /    { name = $2; sub(/:$/, "", name); print theory "." name }')"
  patterns="$(sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' "$ALLOWLIST")"
  while IFS= read -r axiom; do
    [[ -z "$axiom" ]] && continue
    if ! printf '%s\n' "$patterns" | grep -qxF -e "$axiom" -e "${axiom%.*}.*"; then
      printf 'audit: axiom not on the allowlist: %s\n' "$axiom" >&2
      status=1
    fi
  done <<<"$found"
  while IFS= read -r pattern; do
    [[ -z "$pattern" ]] && continue
    if [[ "$pattern" == *'.*' ]]; then
      if ! printf '%s\n' "$found" | grep -qF -e "${pattern%\*}"; then
        printf 'audit: stale allowlist entry: %s\n' "$pattern" >&2
        status=1
      fi
    elif ! printf '%s\n' "$found" | grep -qxF -e "$pattern"; then
      printf 'audit: stale allowlist entry: %s\n' "$pattern" >&2
      status=1
    fi
  done <<<"$patterns"
  if [[ "$status" -eq 0 ]]; then
    echo "audit: axioms passed: $(printf '%s\n' "$found" | grep -c .) axioms, all on the allowlist"
  fi
  return "$status"
}

gate_signoff() {
  if [[ ! -f "$SIGNOFF" ]]; then
    echo "audit: signoff skipped: no definition sign-off is recorded"
    return 0
  fi
  sha256sum --check --quiet "$SIGNOFF"
  echo "audit: signoff passed: the reviewed definitions are unchanged"
}

gates=("$@")
if [[ "${#gates[@]}" -eq 0 ]]; then
  gates=(admits axioms signoff)
fi
for gate in "${gates[@]}"; do
  "gate_$gate"
done
