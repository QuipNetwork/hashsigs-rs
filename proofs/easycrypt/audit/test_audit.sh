#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Self-test of the audit gate: each gate must pass on the tree, and the
# admits, axioms, and signoff gates must fail on their fixtures.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

status=0
expect() {
  local want="$1" label="$2" got=fail log
  shift 2
  log="$(mktemp)"
  if "$@" >"$log" 2>&1; then
    got=pass
  fi
  if [[ "$got" == "$want" ]]; then
    echo "ok: $label ($want)"
  else
    echo "NOT OK: $label: expected $want, got $got" >&2
    sed 's/^/    /' "$log" >&2
    status=1
  fi
  rm -- "$log"
}

expect pass "tree: no admitted proof" audit/audit.sh admits
expect pass "tree: axioms on the allowlist" audit/audit.sh axioms
expect pass "tree: no sign-off, or an intact one" audit/audit.sh signoff
expect fail "fixture: admitted proof" \
  env AUDIT_SOURCES=audit/fixtures/admitted audit/audit.sh admits
expect fail "fixture: axiom not on the allowlist" \
  env AUDIT_PROBE=audit/fixtures/axiom/Probe.ec audit/audit.sh axioms
expect fail "fixture: file changed after the sign-off" \
  env AUDIT_SIGNOFF=audit/fixtures/signoff/SIGNOFF.sha256 audit/audit.sh signoff
exit "$status"
