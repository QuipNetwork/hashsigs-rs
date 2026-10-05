(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Fixture for audit/test_audit.sh: an axiom that the allowlist does not name. *)
require import AllCore.

axiom sneaky : forall (x : int), x = x.

print axiom.
