(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Security game for SHRINCS: existential unforgeability under chosen-message
   attack, for one hybrid key, through the two byte-level verifiers that a
   contract calls. The signer keeps the leaf counter of the stateful key. *)
require import AllCore List IntDiv Distr DList DInterval.
require import ByteDomain Shrincs.

(* ------------------------------------------------------------------ *)
(* Well-formed inputs                                                 *)
(* ------------------------------------------------------------------ *)

(* Every verifier and signer takes a 32-byte hash. *)
op valid_hash (hash : bytes) : bool = is_bytes hash /\ size hash = HASH_LEN.

(* Key generation takes the seed material that the caller supplies. The
   game samples 32 uniform bytes. *)
op dseed : bytes distr = dlist [0..255] 32.

(* ------------------------------------------------------------------ *)
(* Oracle, adversary, game                                            *)
(* ------------------------------------------------------------------ *)

module type SOracle = {
  proc sign(stateful : bool, hash : bytes) : bytes option
}.

module type Adversary (O : SOracle) = {
  proc forge(commitment : bytes, pk : public_key) : bool * bytes * bytes
}.

module O_Sign : SOracle = {
  var k : keys
  var pk : public_key
  var stateless : int          (* stateless signatures issued *)
  var signed_sf : bytes list   (* the hashes signed on the stateful path *)
  var signed_sl : bytes list   (* the hashes signed on the stateless path *)
  var leaves : int list        (* the stateful leaves used *)

  proc init(k0 : keys, pk0 : public_key) : unit = {
    k <- k0;
    pk <- pk0;
    stateless <- 0;
    signed_sf <- [];
    signed_sl <- [];
    leaves <- [];
  }

  proc sign(stateful : bool, hash : bytes) : bytes option = {
    var envelope : bytes option;
    var r : (bytes * keys) option;
    var s : stateless_sig option;

    envelope <- None;
    if (valid_hash hash) {
      if (stateful) {
        (* Stateful path: the next leaf, then the counter moves on. *)
        r <- shrincs_sign k hash;
        if (r <> None) {
          leaves <- k.`ks_next_leaf :: leaves;
          k <- (oget r).`2;
          envelope <- Some (oget r).`1;
          signed_sf <- hash :: signed_sf;
        }
      } else {
        (* Stateless path, up to the budget of the profile. *)
        if (stateless < STATELESS_SIGNATURE_LIMIT) {
          s <- sign_stateless_adapter k pk hash;
          if (s <> None) {
            envelope <- Some (encode_stateless_envelope pk (oget s));
            stateless <- stateless + 1;
            signed_sl <- hash :: signed_sl;
          }
        }
      }
    }
    return envelope;
  }
}.

module EUF_CMA (A : Adversary) = {
  proc main(max_signatures : int) : bool = {
    var seed, hash, envelope : bytes;
    var kp : (keys * public_key) option;
    var stateful, valid, fresh : bool;

    seed <$ dseed;
    kp <- shrincs_keygen seed max_signatures;
    valid <- false;
    fresh <- false;
    if (kp <> None) {
      O_Sign.init((oget kp).`1, (oget kp).`2);
      (stateful, hash, envelope) <@ A(O_Sign).forge((oget kp).`2.`pk_commitment, (oget kp).`2);
      if (stateful) {
        valid <- valid_hash hash /\
                 shrincs_verify (oget kp).`2.`pk_commitment hash envelope = Valid;
        fresh <- ! (hash \in O_Sign.signed_sf);
      } else {
        valid <- valid_hash hash /\
                 shrincs_verify_stateless (oget kp).`2.`pk_commitment hash envelope = Valid;
        fresh <- ! (hash \in O_Sign.signed_sl);
      }
    }
    return valid /\ fresh;
  }
}.
