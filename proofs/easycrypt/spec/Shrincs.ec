(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* SHRINCS at the profile shrincs-256s-keccak (src/profiles/p256s.rs).
   PROFILE_NAME is the ASCII string "shrincs-256s-keccak", and PROFILE_ID is
   its Keccak-256 hash. The known-answer test group `helpers` checks that
   equation. *)
require import AllCore List IntDiv.
require Spec.

clone include Spec with
  op PROFILE_NAME = [115; 104; 114; 105; 110; 99; 115; 45; 50; 53; 54; 115; 45; 107; 101; 99; 99; 97; 107],
  op PROFILE_ID = [50; 245; 115; 180; 83; 255; 196; 179; 237; 181; 219; 92; 140; 111; 16; 217; 42; 174; 96; 214; 183; 116; 145; 22; 168; 102; 81; 245; 110; 42; 72; 120],
  op HASH_TRUNC_LEN = 32,
  op STATELESS_SIGNATURE_LIMIT = 1048576,
  op HYPERTREE_HEIGHT = 64,
  op NUM_HYPERTREE_LAYERS = 8,
  op FORS_TREE_HEIGHT = 14,
  op NUM_FORS_TREES = 22,
  op WOTS_CHAIN_LEN = 16,
  op NUM_WOTS_CHAINS = 64,
  op FORS_C_MAX_GRIND_COUNTER = 16777216,
  op WOTS_TARGET_SUM = 480.
