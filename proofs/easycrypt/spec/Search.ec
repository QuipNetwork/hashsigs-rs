(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Bounded search. `least_from p i n` is the least j with i <= j < n and p j.
   The operator is opaque and has two proven reduction rules, so that an
   evaluation stops at the first hit and never builds the whole range. *)
require import AllCore List.

op [opaque] least_from (p : int -> bool) (i n : int) : int option =
  let j = find p (range i n) in
  if j < n - i then Some (i + j) else None.

lemma least_from_c0 (p : int -> bool) (i n : int) :
  n <= i => least_from p i n = None.
proof. by move=> le_ni @/least_from; rewrite range_geq //= /#. qed.

lemma least_from_cS (p : int -> bool) (i n : int) :
  i < n => least_from p i n = if p i then Some i else least_from p (i + 1) n.
proof.
move=> lt_in @/least_from; rewrite range_ltn //=.
by case: (p i) => _ /=; smt(find_ge0).
qed.

hint simplify least_from_c0, least_from_cS.
