(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Shared representation predicates. This theory depends on neither the
   scheme nor its security game, and assumes no properties of hashing. *)
require import AllCore List IntDiv.

op is_byte (b : int) : bool = 0 <= b < 256.

op is_bytes (bs : int list) : bool = all is_byte bs.

op valid_bytes (width : int) (bs : int list) : bool =
  is_bytes bs /\ size bs = width.

(* Width is in bits. At width zero the only representable value is zero. *)
op valid_uint (bits value : int) : bool =
  0 <= bits /\ 0 <= value < 2 ^ bits.

op valid_u32 (value : int) : bool = valid_uint 32 value.
op valid_u64 (value : int) : bool = valid_uint 64 value.

lemma is_byte_mod256 (x : int) : is_byte (x %% 256).
proof. rewrite /is_byte; smt(modz_ge0 ltz_pmod). qed.

lemma is_bytes_nil : is_bytes [].
proof. by rewrite /is_bytes. qed.

lemma is_bytes_cons (b : int) (bs : int list) :
  is_bytes (b :: bs) <=> is_byte b /\ is_bytes bs.
proof. by rewrite /is_bytes. qed.

lemma is_bytes_cat (xs ys : int list) :
  is_bytes (xs ++ ys) <=> is_bytes xs /\ is_bytes ys.
proof. by rewrite /is_bytes all_cat. qed.

lemma is_bytes_take (n : int) (bs : int list) :
  is_bytes bs => is_bytes (take n bs).
proof. rewrite /is_bytes; smt(allP mem_take). qed.

lemma is_bytes_drop (n : int) (bs : int list) :
  is_bytes bs => is_bytes (drop n bs).
proof. rewrite /is_bytes; smt(allP mem_drop). qed.

lemma is_bytes_nseq (n b : int) :
  is_byte b => is_bytes (nseq n b).
proof. rewrite /is_bytes all_nseq; smt(). qed.

lemma is_bytes_flatten (parts : int list list) :
  all is_bytes parts => is_bytes (flatten parts).
proof.
rewrite /is_bytes; smt(allP flattenP).
qed.

lemma is_bytes_nth (bs : int list) (fallback index : int) :
  is_byte fallback => is_bytes bs => is_byte (nth fallback bs index).
proof.
rewrite /is_bytes; case: (0 <= index < size bs).
+ smt(allP mem_nth).
+ smt(nth_out).
qed.

lemma is_bytes_mkseq (f : int -> int) (n : int) :
  (forall i, 0 <= i < n => is_byte (f i)) => is_bytes (mkseq f n).
proof.
rewrite /is_bytes /mkseq all_map allP.
smt(mem_iota).
qed.

lemma valid_bytes_nonnegative (n : int) (bs : int list) :
  valid_bytes n bs => 0 <= n.
proof. rewrite /valid_bytes; smt(size_ge0). qed.

lemma valid_bytes_cat (n m : int) (xs ys : int list) :
  valid_bytes n xs => valid_bytes m ys =>
  valid_bytes (n + m) (xs ++ ys).
proof. rewrite /valid_bytes is_bytes_cat size_cat; smt(). qed.

lemma valid_bytes_take (n m : int) (bs : int list) :
  valid_bytes m bs => 0 <= n <= m => valid_bytes n (take n bs).
proof.
rewrite /valid_bytes; smt(is_bytes_take size_takel).
qed.

lemma valid_bytes_drop (n m : int) (bs : int list) :
  valid_bytes m bs => 0 <= n <= m => valid_bytes (m - n) (drop n bs).
proof.
rewrite /valid_bytes; smt(is_bytes_drop size_drop).
qed.

lemma valid_bytes_nseq (n b : int) :
  0 <= n => is_byte b => valid_bytes n (nseq n b).
proof. rewrite /valid_bytes size_nseq; smt(is_bytes_nseq). qed.

lemma valid_uint_zero_width (value : int) :
  valid_uint 0 value <=> value = 0.
proof. rewrite /valid_uint expr0 /=; smt(). qed.

lemma valid_u32_range (value : int) :
  valid_u32 value <=> 0 <= value < 2 ^ 32.
proof. by rewrite /valid_u32 /valid_uint. qed.

lemma valid_u64_range (value : int) :
  valid_u64 value <=> 0 <= value < 2 ^ 64.
proof. by rewrite /valid_u64 /valid_uint. qed.
