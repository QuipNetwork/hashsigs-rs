(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Sanity lemmas for the security game. They are not steps of the security
   proof. They show that the game has the properties that the review packet
   states. *)
require import AllCore List IntDiv Distr.
require import Shrincs Games.

(* A key whose leaf counter is past its budget signs nothing on the
   stateful path. *)
lemma exhausted_key_signs_nothing (k : keys) (hash : bytes) :
  k.`ks_max_signatures < k.`ks_next_leaf => shrincs_sign k hash = None.
proof.
move=> past @/shrincs_sign @/sign_stateful_next @/sign_stateful_at_leaf /=.
by rewrite past.
qed.

(* A stateful signature uses the leaf counter, which is at most the budget.
   The new key has the same budget and the next counter. *)
lemma sign_moves_to_next_leaf (k k' : keys) (hash envelope : bytes) :
  k.`ks_max_signatures < 2 ^ 32 - 1 =>
  shrincs_sign k hash = Some (envelope, k') =>
  (0 < k.`ks_next_leaf \/ k.`ks_next_leaf < 0) /\ k.`ks_next_leaf <= k.`ks_max_signatures
  /\ k'.`ks_max_signatures = k.`ks_max_signatures
  /\ k'.`ks_next_leaf = k.`ks_next_leaf + 1.
proof.
move=> small @/shrincs_sign @/sign_stateful_next @/sign_stateful_at_leaf /=.
case: (k.`ks_next_leaf = 0 \/ k.`ks_max_signatures < k.`ks_next_leaf) => //= in_range.
case: (sign_stateful_wots_c _ _ _ _ _) => //= w [_ <-] @/keys_with_next /=.
smt().
qed.

(* The leaves that the oracle has used are pairwise different, and each
   one is below the current leaf counter. *)
op one_time (next : int) (leaves : int list) : bool =
  uniq leaves /\ all (fun leaf => leaf < next) leaves.

lemma O_Sign_one_time :
  hoare [O_Sign.sign :
    O_Sign.k.`ks_max_signatures < 2 ^ 32 - 1 /\ one_time O_Sign.k.`ks_next_leaf O_Sign.leaves ==>
    O_Sign.k.`ks_max_signatures < 2 ^ 32 - 1 /\ one_time O_Sign.k.`ks_next_leaf O_Sign.leaves].
proof.
proc; auto => /> &hr small uq below _ _ signed.
have := sign_moves_to_next_leaf O_Sign.k{hr} (oget (shrincs_sign O_Sign.k{hr} hash{hr})).`2
          hash{hr} (oget (shrincs_sign O_Sign.k{hr} hash{hr})).`1 small.
move: signed; case: (shrincs_sign O_Sign.k{hr} hash{hr}) => //= -[envelope k'] /=.
move=> _ [_ [le_max [-> ->]]]; smt(allP).
qed.

(* The oracle never exceeds the stateless budget. *)
lemma O_Sign_budget :
  hoare [O_Sign.sign :
    O_Sign.stateless <= STATELESS_SIGNATURE_LIMIT ==> O_Sign.stateless <= STATELESS_SIGNATURE_LIMIT].
proof.
proc; sp 1; if; last by auto.
if; first by auto.
if; last by auto.
sp 1; if; last by auto.
(* Generalize the signing term first: a hypothesis that mentions it makes
   the intro patterns and smt reduce the whole specification. *)
wp; skip => &hr.
move: (sign_stateless_adapter O_Sign.k{hr} O_Sign.pk{hr} hash{hr}) (valid_hash hash{hr}) => x v.
smt().
qed.

(* The stateful verifier never accepts the empty envelope. *)
lemma empty_envelope_not_valid (key hash : bytes) : shrincs_verify key hash [] <> Valid.
proof.
by rewrite /shrincs_verify /=; case: (word32 key = None).
qed.

(* An adversary that returns the empty envelope never wins. *)
module A_Empty (O : SOracle) = {
  proc forge(commitment : bytes, pk : public_key) : bool * bytes * bytes = {
    return (true, nseq HASH_LEN 0, []);
  }
}.

lemma A_Empty_loses : hoare [EUF_CMA(A_Empty).main : true ==> !res].
proof.
proc; inline *; auto => &hr _ seed _.
move: (shrincs_keygen seed max_signatures{hr}) => kp.
by case: (kp <> None) => //= _; rewrite empty_envelope_not_valid.
qed.
