(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Reachable counter ranges and oracle bookkeeping. These results do not
   assume cryptographic properties of Keccak or establish unforgeability. *)
require import AllCore List IntDiv Distr.
require import Shrincs Games GamesSanity.

(* The tightened lower-bound guard agrees with the previous definition
   on every Rust u32 input, including invalid zero/excessive budgets. *)
lemma shrincs_keygen_unsigned (seed : bytes) (budget : int) :
  0 <= budget < 2 ^ 32 =>
  shrincs_keygen seed budget =
    if budget = 0 \/ MAX_STATEFUL_SIGNATURES_LIMIT < budget then None
    else Some (build_keys seed budget (keygen_from_master_seed seed)).
proof.
move=> unsigned; rewrite /shrincs_keygen.
have -> : (budget <= 0) = (budget = 0) by smt().
done.
qed.

lemma shrincs_keygen_invalid_budget (seed : bytes) (budget : int) :
  !valid_budget budget => shrincs_keygen seed budget = None.
proof.
move=> invalid; rewrite /shrincs_keygen.
have -> : budget <= 0 \/ MAX_STATEFUL_SIGNATURES_LIMIT < budget
  by move: invalid; rewrite /valid_budget; smt().
done.
qed.

lemma build_keys_counter (seed : bytes) (budget : int)
    (stateless : bytes * bytes * bytes * bytes) :
  valid_budget budget =>
  valid_counter_state (build_keys seed budget stateless).`1 /\
  (build_keys seed budget stateless).`1.`ks_max_signatures = budget /\
  (build_keys seed budget stateless).`1.`ks_next_leaf = 1.
proof.
rewrite /valid_counter_state /build_keys /INITIAL_STATEFUL_LEAF_INDEX /=.
rewrite /valid_budget; smt().
qed.

lemma shrincs_keygen_counter (seed : bytes) (budget : int) (k : keys) (pk : public_key) :
  shrincs_keygen seed budget = Some (k, pk) =>
  valid_counter_state k /\ k.`ks_max_signatures = budget /\ k.`ks_next_leaf = 1.
proof.
rewrite /shrincs_keygen.
case: (budget <= 0 \/ MAX_STATEFUL_SIGNATURES_LIMIT < budget) => //= accepted.
have vb : valid_budget budget by rewrite /valid_budget; smt().
have := build_keys_counter seed budget (keygen_from_master_seed seed) vb.
by case: (build_keys seed budget (keygen_from_master_seed seed)) => k0 pk0 /= facts [<- _].
qed.

lemma valid_counter_unsigned (k : keys) :
  valid_counter_state k =>
  0 <= k.`ks_max_signatures < 2 ^ 32 - 1 /\
  0 <= k.`ks_next_leaf < 2 ^ 32.
proof.
rewrite /valid_counter_state /valid_budget /MAX_STATEFUL_SIGNATURES_LIMIT.
have pow32 : 2 ^ 32 = 4294967296 by ring.
rewrite pow32.
smt().
qed.

lemma shrincs_sign_counter (k k' : keys) (hash envelope : bytes) :
  valid_counter_state k =>
  shrincs_sign k hash = Some (envelope, k') =>
  valid_counter_state k' /\
  1 <= k.`ks_next_leaf <= k.`ks_max_signatures /\
  k'.`ks_max_signatures = k.`ks_max_signatures /\
  k'.`ks_next_leaf = k.`ks_next_leaf + 1.
proof.
move=> valid signed.
have small : k.`ks_max_signatures < 2 ^ 32 - 1
  by have := valid_counter_unsigned k valid; smt().
have step := sign_moves_to_next_leaf k k' hash envelope small signed.
move: valid step; rewrite /valid_counter_state; smt().
qed.

lemma valid_exhausted_key_signs_nothing (k : keys) (hash : bytes) :
  valid_counter_state k =>
  k.`ks_next_leaf = k.`ks_max_signatures + 1 => shrincs_sign k hash = None.
proof.
move=> _ exhausted; apply exhausted_key_signs_nothing; smt().
qed.

(* An unsuccessful/invalid request must also preserve this conjunction.
   Histories and byte-level key well-formedness are separate obligations. *)
op oracle_counter_invariant (k : keys) (stateless : int) (leaves : int list) : bool =
  valid_counter_state k /\ one_time k.`ks_next_leaf leaves /\
  0 <= stateless <= STATELESS_SIGNATURE_LIMIT.

lemma O_Sign_init_counter :
  hoare [O_Sign.init : valid_counter_state k0 ==>
    oracle_counter_invariant O_Sign.k O_Sign.stateless O_Sign.leaves].
proof.
proc; auto; rewrite /oracle_counter_invariant /one_time /STATELESS_SIGNATURE_LIMIT /=.
qed.

lemma O_Sign_preserves_counter :
  hoare [O_Sign.sign :
    oracle_counter_invariant O_Sign.k O_Sign.stateless O_Sign.leaves ==>
    oracle_counter_invariant O_Sign.k O_Sign.stateless O_Sign.leaves].
proof.
proc; sp 1; if; last by auto.
if.
+ sp 1; if; last by auto.
  wp; skip => &hr.
  rewrite /oracle_counter_invariant /one_time.
  move=> [[-> [[[_ [valid [once bounded]]] _] _]] signed].
  have := shrincs_sign_counter O_Sign.k{hr}
    (oget (shrincs_sign O_Sign.k{hr} hash{hr})).`2 hash{hr}
    (oget (shrincs_sign O_Sign.k{hr} hash{hr})).`1 valid.
  move: signed; case: (shrincs_sign O_Sign.k{hr} hash{hr}) => //= -[envelope k'] /=.
  smt(allP).
+ if; last by auto.
  sp 1; if; last by auto.
  wp; skip => &hr.
  move: (sign_stateless_adapter O_Sign.k{hr} O_Sign.pk{hr} hash{hr}) (valid_hash hash{hr}) => s v.
  rewrite /oracle_counter_invariant.
  smt().
qed.

(* This includes invalid hashes, exhausted budgets, and failed searches;
   a request returning None changes none of the persistent oracle state. *)
lemma O_Sign_failed_call_unchanged
    (before : keys * public_key * int * bytes list * bytes list * int list) :
  hoare [O_Sign.sign :
    (O_Sign.k, O_Sign.pk, O_Sign.stateless, O_Sign.signed_sf,
     O_Sign.signed_sl, O_Sign.leaves) = before ==>
    res = None =>
    (O_Sign.k, O_Sign.pk, O_Sign.stateless, O_Sign.signed_sf,
     O_Sign.signed_sl, O_Sign.leaves) = before].
proof. by proc; auto. qed.
