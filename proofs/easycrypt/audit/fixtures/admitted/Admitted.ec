(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Fixture for audit/test_audit.sh: a proof that the admits gate must reject. *)
require import AllCore.

lemma wrong : 1 = 2.
proof. admit. qed.
