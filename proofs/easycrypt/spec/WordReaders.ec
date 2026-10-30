(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Contracts for the existing ABI word readers. read_usize models the
   64-bit payload domain; these results do not establish Rust refinement
   or the cursor/high-water and composite-codec properties. *)
require import AllCore List ByteDomain.
require import Shrincs ByteEncoding IntegerEncoding.

lemma read_word_some (data word : bytes) (pos : int) :
  read_word data pos = Some word <=>
    0 <= pos /\ pos + HASH_LEN <= size data /\
    word = take HASH_LEN (drop pos data).
proof.
rewrite /read_word.
case: (pos < 0 \/ size data < pos + HASH_LEN) => /=; smt().
qed.

lemma read_word_none (data : bytes) (pos : int) :
  read_word data pos = None <=>
    pos < 0 \/ size data < pos + HASH_LEN.
proof. by rewrite /read_word; case: (pos < 0 \/ size data < pos + HASH_LEN). qed.

lemma read_word_valid (data word : bytes) (pos : int) :
  is_bytes data => read_word data pos = Some word => valid_word32 word.
proof.
move=> valid /read_word_some [nonnegative [fits ->]].
rewrite /valid_word32 /valid_bytes.
have valid_suffix := is_bytes_drop pos data valid.
have suffix_size := size_drop pos data nonnegative.
have length : size (take HASH_LEN (drop pos data)) = HASH_LEN
  by apply size_takel; move: fits suffix_size; rewrite /HASH_LEN; smt().
smt(is_bytes_take).
qed.

(* Arbitrary prefixes and suffixes are allowed, including unaligned
   offsets and trailing bytes. Word readers do not check whole inputs. *)
lemma read_word_cat (prefix word suffix : bytes) :
  size word = HASH_LEN =>
  read_word (prefix ++ (word ++ suffix)) (size prefix) = Some word.
proof.
move=> length; apply read_word_some.
rewrite !size_cat drop_size_cat // take_size_cat //.
smt(size_ge0).
qed.

lemma word_from_u32_parts (value : int) :
  take 28 (word_from_u32 value) = nseq 28 0 /\
  drop 28 (word_from_u32 value) = be32 value.
proof.
rewrite /word_from_u32; split.
+ by apply take_size_cat; rewrite size_nseq.
+ by apply drop_size_cat; rewrite size_nseq.
qed.

lemma word_from_usize_parts (value : int) :
  take 24 (word_from_usize value) = nseq 24 0 /\
  drop 24 (word_from_usize value) = be64 value.
proof.
rewrite /word_from_usize; split.
+ by apply take_size_cat; rewrite size_nseq.
+ by apply drop_size_cat; rewrite size_nseq.
qed.

lemma read_u32_some (data : bytes) (pos value : int) :
  read_u32 data pos = Some value <=>
    0 <= pos /\ pos + HASH_LEN <= size data /\
    take 28 (take HASH_LEN (drop pos data)) = nseq 28 0 /\
    value = int_from_bytes (drop 28 (take HASH_LEN (drop pos data))).
proof.
rewrite /read_u32 /read_word.
case: (pos < 0 \/ size data < pos + HASH_LEN) => /=.
+ smt().
+ case: (take 28 (take HASH_LEN (drop pos data)) = nseq 28 0) => /=; smt().
qed.

lemma read_usize_some (data : bytes) (pos value : int) :
  read_usize data pos = Some value <=>
    0 <= pos /\ pos + HASH_LEN <= size data /\
    take 24 (take HASH_LEN (drop pos data)) = nseq 24 0 /\
    value = int_from_bytes (drop 24 (take HASH_LEN (drop pos data))).
proof.
rewrite /read_usize /read_word.
case: (pos < 0 \/ size data < pos + HASH_LEN) => /=.
+ smt().
+ case: (take 24 (take HASH_LEN (drop pos data)) = nseq 24 0) => /=; smt().
qed.

lemma read_u32_none (data : bytes) (pos : int) :
  read_u32 data pos = None <=>
    pos < 0 \/ size data < pos + HASH_LEN \/
    take 28 (take HASH_LEN (drop pos data)) <> nseq 28 0.
proof.
rewrite /read_u32 /read_word.
case: (pos < 0 \/ size data < pos + HASH_LEN) => /=.
+ smt().
+ case: (take 28 (take HASH_LEN (drop pos data)) = nseq 28 0) => /=; smt().
qed.

lemma read_usize_none (data : bytes) (pos : int) :
  read_usize data pos = None <=>
    pos < 0 \/ size data < pos + HASH_LEN \/
    take 24 (take HASH_LEN (drop pos data)) <> nseq 24 0.
proof.
rewrite /read_usize /read_word.
case: (pos < 0 \/ size data < pos + HASH_LEN) => /=.
+ smt().
+ case: (take 24 (take HASH_LEN (drop pos data)) = nseq 24 0) => /=; smt().
qed.

lemma read_u32_encoded_word (data : bytes) (pos value : int) :
  valid_u32 value =>
  read_word data pos = Some (word_from_u32 value) =>
  read_u32 data pos = Some value.
proof.
move=> range word_read.
have [padding payload] := word_from_u32_parts value.
by rewrite /read_u32 word_read /= padding payload (be32_roundtrip value range).
qed.

lemma read_usize_encoded_word (data : bytes) (pos value : int) :
  valid_u64 value =>
  read_word data pos = Some (word_from_usize value) =>
  read_usize data pos = Some value.
proof.
move=> range word_read.
have [padding payload] := word_from_usize_parts value.
by rewrite /read_usize word_read /= padding payload (be64_roundtrip value range).
qed.

lemma read_u32_roundtrip (prefix suffix : bytes) (value : int) :
  valid_u32 value =>
  read_u32 (prefix ++ (word_from_u32 value ++ suffix)) (size prefix) = Some value.
proof.
move=> range; apply read_u32_encoded_word => //.
apply read_word_cat.
have := word_from_u32_valid value; rewrite /valid_word32 /valid_bytes; smt().
qed.

lemma read_usize_roundtrip (prefix suffix : bytes) (value : int) :
  valid_u64 value =>
  read_usize (prefix ++ (word_from_usize value ++ suffix)) (size prefix) = Some value.
proof.
move=> range; apply read_usize_encoded_word => //.
apply read_word_cat.
have := word_from_usize_valid value; rewrite /valid_word32 /valid_bytes; smt().
qed.

(* Byte validity is essential for range and reverse-encoding results:
   the raw integer-list readers check bounds and high zero padding only. *)
lemma read_u32_some_valid (data : bytes) (pos value : int) :
  is_bytes data => read_u32 data pos = Some value =>
  valid_u32 value /\ take HASH_LEN (drop pos data) = word_from_u32 value.
proof.
move=> valid /read_u32_some [nonnegative [fits [padding ->]]].
have word_read : read_word data pos = Some (take HASH_LEN (drop pos data))
  by rewrite read_word_some; smt().
have word_valid := read_word_valid data (take HASH_LEN (drop pos data)) pos valid word_read.
have payload_valid : valid_bytes 4 (drop 28 (take HASH_LEN (drop pos data))).
+ have := valid_bytes_drop 28 HASH_LEN (take HASH_LEN (drop pos data)).
  move: word_valid; rewrite /valid_word32 /HASH_LEN; smt().
split.
+ exact: (int_from_bytes_u32 _ payload_valid).
+ by rewrite /word_from_u32 (be32_reverse _ payload_valid) -padding cat_take_drop.
qed.

lemma read_usize_some_valid (data : bytes) (pos value : int) :
  is_bytes data => read_usize data pos = Some value =>
  valid_u64 value /\ take HASH_LEN (drop pos data) = word_from_usize value.
proof.
move=> valid /read_usize_some [nonnegative [fits [padding ->]]].
have word_read : read_word data pos = Some (take HASH_LEN (drop pos data))
  by rewrite read_word_some; smt().
have word_valid := read_word_valid data (take HASH_LEN (drop pos data)) pos valid word_read.
have payload_valid : valid_bytes 8 (drop 24 (take HASH_LEN (drop pos data))).
+ have := valid_bytes_drop 24 HASH_LEN (take HASH_LEN (drop pos data)).
  move: word_valid; rewrite /valid_word32 /HASH_LEN; smt().
split.
+ exact: (int_from_bytes_u64 _ payload_valid).
+ by rewrite /word_from_usize (be64_reverse _ payload_valid) -padding cat_take_drop.
qed.

(* These iff contracts characterize the single word at pos. They do not
   require alignment or exclude trailing data; composite codecs must
   establish their own offsets, whole-input checks, and round trips. *)
lemma read_u32_canonical (data : bytes) (pos value : int) :
  is_bytes data =>
  (read_u32 data pos = Some value <=>
    0 <= pos /\ pos + HASH_LEN <= size data /\ valid_u32 value /\
    take HASH_LEN (drop pos data) = word_from_u32 value).
proof.
move=> valid; split.
+ move=> success.
  have := read_u32_some_valid data pos value valid success.
  move: success; rewrite read_u32_some; smt().
+ move=> [nonnegative [fits [range encoded]]].
  apply (read_u32_encoded_word data pos value range).
  rewrite read_word_some; smt().
qed.

lemma read_usize_canonical (data : bytes) (pos value : int) :
  is_bytes data =>
  (read_usize data pos = Some value <=>
    0 <= pos /\ pos + HASH_LEN <= size data /\ valid_u64 value /\
    take HASH_LEN (drop pos data) = word_from_usize value).
proof.
move=> valid; split.
+ move=> success.
  have := read_usize_some_valid data pos value valid success.
  move: success; rewrite read_usize_some; smt().
+ move=> [nonnegative [fits [range encoded]]].
  apply (read_usize_encoded_word data pos value range).
  rewrite read_word_some; smt().
qed.
