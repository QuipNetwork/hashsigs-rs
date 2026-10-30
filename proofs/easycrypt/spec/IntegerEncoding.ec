(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Big-endian integer round trips. These lemmas connect the existing
   encoders and decoder without changing their implementations. *)
require import AllCore List IntDiv ByteDomain.
require import Shrincs ByteEncoding.

lemma byte_div_shift (value exponent : int) :
  0 <= exponent =>
  value %/ 256 %/ (256 ^ exponent) = value %/ (256 ^ (exponent + 1)).
proof. by move=> nonnegative; rewrite exprS // divz_mul. qed.

lemma int_from_bytes_rcons (bs : bytes) (b : int) :
  int_from_bytes (rcons bs b) = int_from_bytes bs * 256 + b.
proof. by rewrite /int_from_bytes foldl_rcons. qed.

(* Peel off the least significant byte, retaining leading zero bytes in
   the prefix. No unsigned value bound is needed for this decomposition. *)
lemma int_to_bytes_succ (value width : int) :
  0 <= width =>
  int_to_bytes value (width + 1) =
    rcons (int_to_bytes (value %/ 256) width) (value %% 256).
proof.
move=> nonnegative; rewrite /int_to_bytes (mkseqS _ width) //.
congr.
+ apply eq_in_mkseq => i bounds.
  have exponent_nonnegative : 0 <= width - 1 - i by smt().
  have := byte_div_shift value (width - 1 - i) exponent_nonnegative.
  smt().
+ smt(expr0 divz1).
qed.

lemma int_from_bytes_range (bs : bytes) :
  is_bytes bs => 0 <= int_from_bytes bs < 256 ^ size bs.
proof.
elim/last_ind: bs => [|bs b ih].
+ by rewrite /int_from_bytes /= expr0.
+ move=> valid.
  have [prefix digit] : is_bytes bs /\ is_byte b
    by move: valid; rewrite -cats1 is_bytes_cat is_bytes_cons is_bytes_nil /=.
  rewrite int_from_bytes_rcons size_rcons exprSr 1:size_ge0.
  have range := ih prefix.
  move: digit; rewrite /is_byte; smt().
qed.

lemma int_from_to_bytes (value width : int) :
  0 <= width => 0 <= value < 256 ^ width =>
  int_from_bytes (int_to_bytes value width) = value.
proof.
elim/natind: width value => [width nonpositive|width nonnegative ih] value.
+ move=> nonnegative.
  have -> : width = 0 by smt().
  rewrite expr0 => range.
  have -> : value = 0 by smt().
  by rewrite /int_to_bytes mkseq0 /int_from_bytes.
+ move=> _ range.
  rewrite int_to_bytes_succ // int_from_bytes_rcons.
  have quotient_range : 0 <= value %/ 256 < 256 ^ width.
  + move: range; rewrite exprSr //; smt(divz_ge0 ltz_divLR).
  rewrite (ih (value %/ 256) nonnegative quotient_range).
  smt(divz_eq).
qed.

lemma int_to_from_bytes_size (bs : bytes) :
  is_bytes bs => int_to_bytes (int_from_bytes bs) (size bs) = bs.
proof.
elim/last_ind: bs => [|bs b ih].
+ by rewrite /int_from_bytes /int_to_bytes /= mkseq0.
+ move=> valid.
  have [prefix digit] : is_bytes bs /\ is_byte b
    by move: valid; rewrite -cats1 is_bytes_cat is_bytes_cons is_bytes_nil /=.
  have small_div : b %/ 256 = 0
    by apply divz_small; move: digit; rewrite /is_byte /=.
  have small_mod : b %% 256 = b
    by apply modz_small; move: digit; rewrite /is_byte /=.
  rewrite size_rcons int_from_bytes_rcons int_to_bytes_succ 1:size_ge0.
  by rewrite divzMDl // modzMDl small_div small_mod /= ih.
qed.

lemma int_to_from_bytes (width : int) (bs : bytes) :
  valid_bytes width bs => int_to_bytes (int_from_bytes bs) width = bs.
proof.
rewrite /valid_bytes => -[valid <-].
exact: (int_to_from_bytes_size bs valid).
qed.

lemma byte_power_u32 : 256 ^ 4 = 2 ^ 32.
proof. by ring. qed.

lemma byte_power_u64 : 256 ^ 8 = 2 ^ 64.
proof. by ring. qed.

lemma be32_roundtrip (value : int) :
  valid_u32 value => int_from_bytes (be32 value) = value.
proof.
move=> /valid_u32_range range; rewrite /be32.
apply int_from_to_bytes => //.
by rewrite byte_power_u32.
qed.

lemma be64_roundtrip (value : int) :
  valid_u64 value => int_from_bytes (be64 value) = value.
proof.
move=> /valid_u64_range range; rewrite /be64.
apply int_from_to_bytes => //.
by rewrite byte_power_u64.
qed.

lemma be32_reverse (bs : bytes) :
  valid_bytes 4 bs => be32 (int_from_bytes bs) = bs.
proof. rewrite /be32; exact: int_to_from_bytes. qed.

lemma be64_reverse (bs : bytes) :
  valid_bytes 8 bs => be64 (int_from_bytes bs) = bs.
proof. rewrite /be64; exact: int_to_from_bytes. qed.

lemma int_from_bytes_u32 (bs : bytes) :
  valid_bytes 4 bs => valid_u32 (int_from_bytes bs).
proof.
rewrite /valid_bytes valid_u32_range => -[valid length].
have := int_from_bytes_range bs valid.
by rewrite length byte_power_u32.
qed.

lemma int_from_bytes_u64 (bs : bytes) :
  valid_bytes 8 bs => valid_u64 (int_from_bytes bs).
proof.
rewrite /valid_bytes valid_u64_range => -[valid length].
have := int_from_bytes_range bs valid.
by rewrite length byte_power_u64.
qed.
