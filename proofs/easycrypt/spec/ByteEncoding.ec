(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Byte/word shape lemmas. They do not establish integer round trips,
   composite-codec correctness, or any property of the abstract hash. *)
require import AllCore List IntDiv ByteDomain.
require import Shrincs.

lemma int_to_bytes_size (value width : int) :
  0 <= width => size (int_to_bytes value width) = width.
proof. rewrite /int_to_bytes size_mkseq; smt(). qed.

(* Remainders are bytes even outside the unsigned input domain. This
   shape fact does not imply that decoding recovers the original value. *)
lemma int_to_bytes_is_bytes (value width : int) :
  is_bytes (int_to_bytes value width).
proof.
rewrite /int_to_bytes; apply is_bytes_mkseq => i _.
exact: is_byte_mod256.
qed.

lemma int_to_bytes_valid (value width : int) :
  0 <= width => valid_bytes width (int_to_bytes value width).
proof.
rewrite /valid_bytes; smt(int_to_bytes_size int_to_bytes_is_bytes).
qed.

lemma be32_valid (value : int) : valid_bytes 4 (be32 value).
proof. rewrite /be32; exact: (int_to_bytes_valid value 4). qed.

lemma be64_valid (value : int) : valid_bytes 8 (be64 value).
proof. rewrite /be64; exact: (int_to_bytes_valid value 8). qed.

lemma valid_word32_shape (word : bytes) :
  valid_word32 word <=> is_bytes word /\ size word = HASH_LEN.
proof. by rewrite /valid_word32 /valid_bytes. qed.

lemma word32_accepts_valid (word : bytes) :
  valid_word32 word => word32 word = Some word.
proof. by rewrite /valid_word32 /valid_bytes /word32 => -[_ ->]. qed.

lemma word32_some_valid (input word : bytes) :
  is_bytes input => word32 input = Some word =>
  word = input /\ valid_word32 word.
proof.
rewrite /word32 /valid_word32 /valid_bytes.
case: (size input = HASH_LEN) => //=; smt().
qed.

lemma word32_none_valid_input (input : bytes) :
  is_bytes input => (word32 input = None <=> !valid_word32 input).
proof.
rewrite /word32 /valid_word32 /valid_bytes.
case: (size input = HASH_LEN) => //=; smt().
qed.

lemma word_from_u32_valid (value : int) :
  valid_word32 (word_from_u32 value).
proof.
rewrite /valid_word32 /HASH_LEN /word_from_u32.
have zeros : valid_bytes 28 (nseq 28 0)
  by apply valid_bytes_nseq; rewrite /is_byte.
have := valid_bytes_cat 28 4 (nseq 28 0) (be32 value) zeros (be32_valid value).
done.
qed.

lemma word_from_usize_valid (value : int) :
  valid_word32 (word_from_usize value).
proof.
rewrite /valid_word32 /HASH_LEN /word_from_usize.
have zeros : valid_bytes 24 (nseq 24 0)
  by apply valid_bytes_nseq; rewrite /is_byte.
have := valid_bytes_cat 24 8 (nseq 24 0) (be64 value) zeros (be64_valid value).
done.
qed.
