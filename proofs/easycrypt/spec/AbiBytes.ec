(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Offset and length-prefixed byte-string contracts for the existing ABI
   operators. The pure byte reader omits Rust's trailing-padding and
   cursor checks; neither whole-codec correctness nor Rust refinement is
   established here. Lengths/offsets use the model's 64-bit payloads. *)
require import AllCore List IntDiv ByteDomain.
require import Shrincs ByteEncoding IntegerEncoding WordReaders.

lemma pad_len_range (len : int) : 0 <= pad_len len < HASH_LEN.
proof. rewrite /pad_len /HASH_LEN; smt(modz_ge0 ltz_pmod). qed.

lemma pad_len_aligned (len : int) : (len + pad_len len) %% HASH_LEN = 0.
proof.
rewrite /pad_len modzDmr -modzDml.
have -> : len %% HASH_LEN + (HASH_LEN - len %% HASH_LEN) = HASH_LEN by ring.
exact: modzz.
qed.

lemma encode_bytes_size (payload : bytes) :
  size (encode_bytes payload) = HASH_LEN + size payload + pad_len (size payload).
proof.
have word_valid := word_from_usize_valid (size payload).
have padding_range := pad_len_range (size payload).
move: word_valid; rewrite /valid_word32 /valid_bytes /encode_bytes !size_cat size_nseq.
smt().
qed.

lemma encode_bytes_valid (payload : bytes) :
  is_bytes payload =>
  valid_bytes (HASH_LEN + size payload + pad_len (size payload)) (encode_bytes payload).
proof.
move=> valid; rewrite /valid_bytes encode_bytes_size /= /encode_bytes !is_bytes_cat.
have word_valid := word_from_usize_valid (size payload).
have zeros : is_bytes (nseq (pad_len (size payload)) 0)
  by apply is_bytes_nseq; rewrite /is_byte.
move: word_valid; rewrite /valid_word32 /valid_bytes; smt().
qed.

lemma encode_bytes_aligned (payload : bytes) : size (encode_bytes payload) %% HASH_LEN = 0.
proof.
rewrite encode_bytes_size.
have -> : HASH_LEN + size payload + pad_len (size payload) =
    HASH_LEN + (size payload + pad_len (size payload)) by ring.
by rewrite modzDl pad_len_aligned.
qed.

lemma encode_bytes_padding (payload : bytes) :
  drop (HASH_LEN + size payload) (encode_bytes payload) = nseq (pad_len (size payload)) 0.
proof.
have word_valid := word_from_usize_valid (size payload).
have word_length : size (word_from_usize (size payload)) = HASH_LEN
  by move: word_valid; rewrite /valid_word32 /valid_bytes; smt().
rewrite /encode_bytes; apply drop_size_cat.
by rewrite size_cat word_length.
qed.

lemma decode_offset_some (data : bytes) (base head start : int) :
  decode_offset data base head = Some start <=>
    read_usize data head = Some (start - base).
proof.
rewrite /decode_offset; case: (read_usize data head) => [|offset] /=; smt().
qed.

lemma decode_offset_none (data : bytes) (base head : int) :
  decode_offset data base head = None <=> read_usize data head = None.
proof. by rewrite /decode_offset; case: (read_usize data head). qed.

(* Offset resolution checks the head word, not the target. Arithmetic is
   unbounded here; base + offset may lie beyond the input or a Rust usize. *)
lemma decode_offset_valid (data : bytes) (base head start : int) :
  is_bytes data => decode_offset data base head = Some start =>
  0 <= head /\ head + HASH_LEN <= size data /\
  valid_u64 (start - base) /\ base <= start < base + 2 ^ 64.
proof.
move=> valid /decode_offset_some success.
have := read_usize_canonical data head (start - base) valid.
rewrite valid_u64_range; smt().
qed.

lemma decode_offset_cat (prefix suffix : bytes) (base offset : int) :
  valid_u64 offset =>
  decode_offset (prefix ++ (word_from_usize offset ++ suffix)) base (size prefix) =
    Some (base + offset).
proof.
move=> range; by rewrite /decode_offset (read_usize_roundtrip prefix suffix offset range).
qed.

lemma read_bytes_at_some (data payload : bytes) (start : int) :
  read_bytes_at data start = Some payload <=>
    exists len, read_usize data start = Some len /\
      start + HASH_LEN + len <= size data /\
      payload = take len (drop (start + HASH_LEN) data).
proof.
rewrite /read_bytes_at; case: (read_usize data start) => [|len] /=.
+ smt().
+ case: (size data < start + HASH_LEN + len) => /=; smt().
qed.

lemma read_bytes_at_none (data : bytes) (start : int) :
  read_bytes_at data start = None <=>
    read_usize data start = None \/
    exists len, read_usize data start = Some len /\ size data < start + HASH_LEN + len.
proof.
rewrite /read_bytes_at; case: (read_usize data start) => [|len] /=.
+ smt().
+ case: (size data < start + HASH_LEN + len) => /=; smt().
qed.

lemma read_bytes_at_truncated_header (data : bytes) (start : int) :
  start < 0 \/ size data < start + HASH_LEN => read_bytes_at data start = None.
proof. rewrite read_bytes_at_none read_usize_none; smt(). qed.

lemma read_bytes_at_truncated_payload (data : bytes) (start len : int) :
  read_usize data start = Some len => size data < start + HASH_LEN + len =>
  read_bytes_at data start = None.
proof. rewrite read_bytes_at_none; smt(). qed.

lemma read_bytes_at_valid (data payload : bytes) (start : int) :
  is_bytes data => read_bytes_at data start = Some payload =>
  is_bytes payload /\ valid_u64 (size payload) /\
  0 <= start /\ start + HASH_LEN + size payload <= size data /\
  read_usize data start = Some (size payload).
proof.
move=> valid /read_bytes_at_some [len [header [fits ->]]].
have [range _] := read_usize_some_valid data start len valid header.
have [nonnegative _] : 0 <= start /\ start + HASH_LEN <= size data
  by move: header; rewrite read_usize_some; smt().
have len_nonnegative : 0 <= len by move: range; rewrite valid_u64_range; smt().
have suffix_length : size (drop (start + HASH_LEN) data) = size data - (start + HASH_LEN).
+ rewrite size_drop; move: nonnegative fits len_nonnegative; rewrite /HASH_LEN; smt().
have payload_length : size (take len (drop (start + HASH_LEN) data)) = len
  by apply size_takel; smt().
rewrite payload_length; smt(is_bytes_take is_bytes_drop).
qed.

(* No suffix condition is needed: this reader stops at the payload end.
   In particular, it accepts absent, nonzero, or extra trailing padding. *)
lemma read_bytes_at_cat (prefix payload suffix : bytes) :
  valid_u64 (size payload) =>
  read_bytes_at
    (prefix ++ (word_from_usize (size payload) ++ (payload ++ suffix)))
    (size prefix) = Some payload.
proof.
move=> range.
have word_length : size (word_from_usize (size payload)) = HASH_LEN
  by have := word_from_usize_valid (size payload); rewrite /valid_word32 /valid_bytes; smt().
have fits : size prefix + HASH_LEN + size payload <=
    size (prefix ++ (word_from_usize (size payload) ++ (payload ++ suffix)))
  by smt(size_cat size_ge0).
rewrite /read_bytes_at (read_usize_roundtrip prefix (payload ++ suffix) _ range) /=.
rewrite iffalse 1:/#.
have consumed : size (prefix ++ word_from_usize (size payload)) = size prefix + HASH_LEN
  by rewrite size_cat word_length.
by rewrite catA -consumed drop_size_cat // take_size_cat.
qed.

lemma read_bytes_at_encode_cat (prefix payload suffix : bytes) :
  valid_u64 (size payload) =>
  read_bytes_at (prefix ++ (encode_bytes payload ++ suffix)) (size prefix) = Some payload.
proof.
move=> range; rewrite /encode_bytes.
rewrite -(catA (word_from_usize (size payload) ++ payload) (nseq (pad_len (size payload)) 0) suffix).
rewrite -(catA (word_from_usize (size payload)) payload (nseq (pad_len (size payload)) 0 ++ suffix)).
exact: (read_bytes_at_cat prefix payload (nseq (pad_len (size payload)) 0 ++ suffix) range).
qed.

lemma read_bytes_at_roundtrip (payload : bytes) :
  valid_u64 (size payload) => read_bytes_at (encode_bytes payload) 0 = Some payload.
proof.
move=> range; have := read_bytes_at_encode_cat [] payload [] range.
by rewrite /= cats0.
qed.

lemma read_bytes_at_unpadded (payload : bytes) :
  valid_u64 (size payload) =>
  read_bytes_at (word_from_usize (size payload) ++ payload) 0 = Some payload.
proof.
move=> range; have := read_bytes_at_cat [] payload [] range.
by rewrite /= cats0.
qed.

(* A checked family of counterexamples to whole-input canonicality of
   this low-level reader. Top-level re-encoding checks need further proofs. *)
lemma read_bytes_at_missing_padding (payload : bytes) :
  valid_u64 (size payload) => 0 < pad_len (size payload) =>
  read_bytes_at (word_from_usize (size payload) ++ payload) 0 = Some payload /\
  word_from_usize (size payload) ++ payload <> encode_bytes payload.
proof.
move=> range positive; split; first exact: (read_bytes_at_unpadded payload range).
have word_length : size (word_from_usize (size payload)) = HASH_LEN
  by have := word_from_usize_valid (size payload); rewrite /valid_word32 /valid_bytes; smt().
have encoded_length := encode_bytes_size payload.
smt(size_cat).
qed.

lemma encode_bytes_injective (xs ys : bytes) :
  valid_u64 (size xs) => valid_u64 (size ys) =>
  encode_bytes xs = encode_bytes ys => xs = ys.
proof.
move=> range_xs range_ys equal.
have := read_bytes_at_roundtrip xs range_xs.
have := read_bytes_at_roundtrip ys range_ys.
smt().
qed.

lemma decode_bytes_resolved (data : bytes) (base head start : int) :
  decode_offset data base head = Some start =>
  decode_bytes data base head = read_bytes_at data start.
proof. by move=> resolved; rewrite /decode_bytes resolved. qed.

lemma decode_bytes_some (data payload : bytes) (base head : int) :
  decode_bytes data base head = Some payload <=>
    exists start, decode_offset data base head = Some start /\
      read_bytes_at data start = Some payload.
proof.
rewrite /decode_bytes; case: (decode_offset data base head) => [|start] /=; smt().
qed.

lemma decode_bytes_none (data : bytes) (base head : int) :
  decode_bytes data base head = None <=>
    decode_offset data base head = None \/
    exists start, decode_offset data base head = Some start /\ read_bytes_at data start = None.
proof.
rewrite /decode_bytes; case: (decode_offset data base head) => [|start] /=; smt().
qed.

(* A relative head pointing past itself to an encoded byte string, inside
   arbitrary surrounding data. This is not yet a theorem about encode_tuple. *)
lemma decode_bytes_roundtrip (prefix payload suffix : bytes) :
  valid_u64 (size payload) =>
  decode_bytes
    (prefix ++ (word_from_usize HASH_LEN ++ (encode_bytes payload ++ suffix)))
    (size prefix) (size prefix) = Some payload.
proof.
move=> range.
have power64 : 2 ^ 64 = 18446744073709551616 by ring.
have offset_range : valid_u64 HASH_LEN by rewrite valid_u64_range /HASH_LEN power64.
have resolved := decode_offset_cat prefix (encode_bytes payload ++ suffix)
    (size prefix) HASH_LEN offset_range.
rewrite (decode_bytes_resolved _ _ _ _ resolved).
have word_length : size (word_from_usize HASH_LEN) = HASH_LEN
  by have := word_from_usize_valid HASH_LEN; rewrite /valid_word32 /valid_bytes; smt().
have consumed : size (prefix ++ word_from_usize HASH_LEN) = size prefix + HASH_LEN
  by rewrite size_cat word_length.
rewrite catA -consumed.
exact: (read_bytes_at_encode_cat (prefix ++ word_from_usize HASH_LEN) payload suffix range).
qed.
