(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Fixed-size bytes32[] ABI contracts. These lemmas use the existing
   all_some/mkseq decoder and preserve its element order. They do not
   establish general tuple codecs or source-linked Rust refinement. *)
require import AllCore List ByteDomain.
require import Shrincs ByteEncoding IntegerEncoding WordReaders AbiBytes.

lemma all_some_cons ['a] (value : 'a option) (xs : 'a option list) :
  all_some (value :: xs) =
    obind (fun x => omap (fun ys => x :: ys) (all_some xs)) value.
proof.
rewrite /all_some; case: value => [|x] /=;
  case: (has (fun o => o = None) xs) => /=; smt().
qed.

lemma all_some_map_some ['a] (xs : 'a list) : all_some (map Some xs) = Some xs.
proof.
elim: xs => [|x xs ih]; first by rewrite /all_some.
by rewrite map_cons all_some_cons ih.
qed.

lemma all_some_some ['a] (xs : 'a option list) (ys : 'a list) :
  all_some xs = Some ys <=> xs = map Some ys.
proof.
split; last by move=> ->; rewrite all_some_map_some.
rewrite /all_some; case: (has (fun o => o = None) xs) => //= absent.
move=> decoded.
have identity : map (fun o : 'a option => Some (oget o)) xs = map idfun xs.
+ apply eq_in_map => o member.
  have nonempty : o <> None by move: absent; rewrite hasPn; smt().
  by case: o member nonempty.
by rewrite -decoded -map_comp identity map_id.
qed.

lemma all_some_none ['a] (xs : 'a option list) :
  all_some xs = None <=> has (fun o => o = None) xs.
proof. by rewrite /all_some; case: (has (fun o => o = None) xs). qed.

lemma all_some_mkseq_none ['a] (f : int -> 'a option) (count : int) :
  all_some (mkseq f count) = None <=>
    exists i, 0 <= i < count /\ f i = None.
proof. rewrite all_some_none hasP; smt(mkseqP). qed.

lemma all_some_mkseq_some ['a] (f : int -> 'a option) (count : int) (xs : 'a list) (fallback : 'a) :
  0 <= count =>
  (all_some (mkseq f count) = Some xs <=>
    size xs = count /\ forall i, 0 <= i < count => f i = Some (nth fallback xs i)).
proof.
move=> nonnegative; rewrite all_some_some; split.
+ move=> equal.
  have length : size xs = count by smt(size_mkseq size_map).
  split => // i bounds.
  have point : nth None (mkseq f count) i = nth None (map Some xs) i by rewrite equal.
  move: point.
  rewrite nth_mkseq // (nth_map fallback) //; smt().
+ move=> [length entries]; apply (eq_from_nth None).
  + rewrite size_mkseq size_map length; smt().
  + move=> i bounds.
    have range : 0 <= i < count by move: bounds; rewrite size_mkseq; smt().
    rewrite nth_mkseq // (nth_map fallback) 1:/#.
    exact: (entries i range).
qed.

lemma word_array_flatten_size (items : bytes list) :
  all valid_word32 items => size (flatten items) = HASH_LEN * size items.
proof.
move=> valid; apply size_flatten_ctt => word member.
have : valid_word32 word by move: valid; rewrite allP; smt().
rewrite /valid_word32 /valid_bytes; smt().
qed.

lemma word_array_flatten_valid (items : bytes list) :
  all valid_word32 items => is_bytes (flatten items).
proof.
move=> valid; apply is_bytes_flatten.
move: valid; rewrite !allP /valid_word32 /valid_bytes; smt().
qed.

lemma word_array_nth_valid (items : bytes list) (i : int) :
  all valid_word32 items => 0 <= i < size items => valid_word32 (nth [] items i).
proof. rewrite allP; smt(mem_nth). qed.

lemma encode_bytes32_array_size (items : bytes list) :
  all valid_word32 items =>
  size (encode_bytes32_array items) = HASH_LEN + HASH_LEN * size items.
proof.
move=> valid.
have word_length : size (word_from_usize (size items)) = HASH_LEN
  by have := word_from_usize_valid (size items); rewrite /valid_word32 /valid_bytes; smt().
by rewrite /encode_bytes32_array size_cat word_length (word_array_flatten_size items valid).
qed.

lemma encode_bytes32_array_valid (items : bytes list) :
  all valid_word32 items =>
  valid_bytes (HASH_LEN + HASH_LEN * size items) (encode_bytes32_array items).
proof.
move=> valid; rewrite /valid_bytes (encode_bytes32_array_size items valid) /=.
rewrite /encode_bytes32_array is_bytes_cat.
have := word_array_flatten_valid items valid.
have := word_from_usize_valid (size items); rewrite /valid_word32 /valid_bytes; smt().
qed.

lemma word_array_read_nth (prefix suffix : bytes) (items : bytes list) (i : int) :
  all valid_word32 items => 0 <= i < size items =>
  read_word (prefix ++ (flatten items ++ suffix)) (size prefix + HASH_LEN * i) =
    Some (nth [] items i).
proof.
move=> valid bounds.
have width : HASH_LEN = 32 by rewrite /HASH_LEN.
have fixed : forall word, word \in items => size word = HASH_LEN
  by move: valid; rewrite allP /valid_word32 /valid_bytes; smt().
have flattened_length := word_array_flatten_size items valid.
have word_length : size (nth [] items i) = HASH_LEN
  by have := word_array_nth_valid items i valid bounds; rewrite /valid_word32 /valid_bytes; smt().
have extraction :
    take HASH_LEN (drop (size prefix + HASH_LEN * i) (prefix ++ (flatten items ++ suffix))) =
      nth [] items i.
+ rewrite drop_catr 1:/#.
  rewrite (_ : size prefix + HASH_LEN * i - size prefix = HASH_LEN * i) 1:/#.
  rewrite drop_catl 1:/# (drop_flatten_ctt HASH_LEN i items fixed).
  rewrite (drop_nth [] i items bounds) flatten_cons -catA.
  by rewrite take_size_cat.
rewrite read_word_some; smt(size_cat size_ge0).
qed.

(* The lower bound on start and start <= size data cover the empty case.
   In the decoder, the successfully read length word supplies both facts. *)
lemma word_array_reads_none (data : bytes) (start count : int) :
  0 <= start <= size data => 0 <= count =>
  (all_some (mkseq (fun i => read_word data (start + HASH_LEN * i)) count) = None <=>
    size data < start + HASH_LEN * count).
proof.
move=> start_bounds nonnegative.
have width : HASH_LEN = 32 by rewrite /HASH_LEN.
rewrite all_some_mkseq_none; split.
+ move=> [i [range /read_word_none failed]]; smt().
+ move=> truncated.
  have positive : 0 < count by smt().
  exists (count - 1); split; first smt().
  rewrite read_word_none; smt().
qed.

lemma encode_bytes32_array_length (prefix suffix : bytes) (items : bytes list) :
  valid_u64 (size items) =>
  read_usize (prefix ++ (encode_bytes32_array items ++ suffix)) (size prefix) = Some (size items).
proof.
move=> range; rewrite /encode_bytes32_array.
rewrite -(catA (word_from_usize (size items)) (flatten items) suffix).
exact: (read_usize_roundtrip prefix (flatten items ++ suffix) (size items) range).
qed.

lemma decode_array_bytes32_resolved (data : bytes) (base head maximum start count : int) :
  decode_offset data base head = Some start => read_usize data start = Some count =>
  decode_array_bytes32 data base head maximum =
    if maximum < count then None else
      all_some (mkseq (fun i => read_word data (start + HASH_LEN + HASH_LEN * i)) count).
proof. by move=> offset header; rewrite /decode_array_bytes32 offset /= header. qed.

lemma obind_some_value ['a 'b] (f : 'a -> 'b option) (value : 'a option) (result : 'b) :
  obind f value = Some result <=> exists x, value = Some x /\ f x = Some result.
proof. case: value => [|x] /=; smt(). qed.

lemma decode_array_bytes32_some (data : bytes) (items : bytes list) (base head maximum : int) :
  decode_array_bytes32 data base head maximum = Some items <=>
    exists start count, decode_offset data base head = Some start /\
      read_usize data start = Some count /\ count <= maximum /\
      all_some (mkseq (fun i => read_word data (start + HASH_LEN + HASH_LEN * i)) count) = Some items.
proof.
rewrite /decode_array_bytes32 obind_some_value; split.
+ move=> [start [offset /obind_some_value [count [header collected]]]].
  exists start count; split => //; split => //.
  move: collected; rewrite /=; smt().
+ move=> [start count [offset [header [limit collected]]]].
  exists start; split => //; apply obind_some_value; exists count; split => //.
  by rewrite /= iffalse 1:/#.
qed.

lemma decode_array_bytes32_bad_offset (data : bytes) (base head maximum : int) :
  decode_offset data base head = None => decode_array_bytes32 data base head maximum = None.
proof. by move=> rejected; rewrite /decode_array_bytes32 rejected. qed.

lemma decode_array_bytes32_bad_header (data : bytes) (base head maximum start : int) :
  decode_offset data base head = Some start => read_usize data start = None =>
  decode_array_bytes32 data base head maximum = None.
proof. by move=> offset rejected; rewrite /decode_array_bytes32 offset /= rejected. qed.

lemma decode_array_bytes32_oversized (data : bytes) (base head maximum start count : int) :
  decode_offset data base head = Some start => read_usize data start = Some count =>
  maximum < count => decode_array_bytes32 data base head maximum = None.
proof.
move=> offset header oversized.
by rewrite (decode_array_bytes32_resolved data base head maximum start count offset header) oversized.
qed.

lemma decode_array_bytes32_bounds (data : bytes) (base head maximum start count : int) :
  is_bytes data => decode_offset data base head = Some start =>
  read_usize data start = Some count =>
  (decode_array_bytes32 data base head maximum = None <=>
    maximum < count \/ size data < start + HASH_LEN + HASH_LEN * count).
proof.
move=> valid offset header.
have [range _] := read_usize_some_valid data start count valid header.
have nonnegative : 0 <= count by move: range; rewrite valid_u64_range; smt().
have start_bounds : 0 <= start + HASH_LEN <= size data
  by move: header; rewrite read_usize_some /HASH_LEN; smt().
rewrite (decode_array_bytes32_resolved data base head maximum start count offset header).
case: (maximum < count) => //=.
have := word_array_reads_none data (start + HASH_LEN) count start_bounds nonnegative.
smt().
qed.

lemma decode_array_bytes32_truncated_header (data : bytes) (base head maximum start : int) :
  decode_offset data base head = Some start =>
  start < 0 \/ size data < start + HASH_LEN =>
  decode_array_bytes32 data base head maximum = None.
proof.
move=> offset truncated.
apply (decode_array_bytes32_bad_header data base head maximum start offset).
rewrite read_usize_none; smt().
qed.

lemma decode_array_bytes32_truncated_elements (data : bytes) (base head maximum start count : int) :
  is_bytes data => decode_offset data base head = Some start =>
  read_usize data start = Some count => size data < start + HASH_LEN + HASH_LEN * count =>
  decode_array_bytes32 data base head maximum = None.
proof.
move=> valid offset header truncated.
have := decode_array_bytes32_bounds data base head maximum start count valid offset header.
smt().
qed.

(* The returned count equals the length word, and each returned element
   is the successful read at its original index. No sorting/deduplication. *)
lemma decode_array_bytes32_entries (data : bytes) (items : bytes list) (base head maximum : int) :
  is_bytes data => decode_array_bytes32 data base head maximum = Some items =>
  exists start, decode_offset data base head = Some start /\
    read_usize data start = Some (size items) /\ size items <= maximum /\
    forall i, 0 <= i < size items =>
      read_word data (start + HASH_LEN + HASH_LEN * i) = Some (nth [] items i).
proof.
move=> valid /decode_array_bytes32_some [start count [offset [header [limit collected]]]].
have [range _] := read_usize_some_valid data start count valid header.
have nonnegative : 0 <= count by move: range; rewrite valid_u64_range; smt().
have [length entries] : size items = count /\
    forall i, 0 <= i < count =>
      read_word data (start + HASH_LEN + HASH_LEN * i) = Some (nth [] items i)
  by move: collected; rewrite (all_some_mkseq_some _ count items [] nonnegative).
exists start; smt().
qed.

lemma decode_array_bytes32_valid (data : bytes) (items : bytes list) (base head maximum : int) :
  is_bytes data => decode_array_bytes32 data base head maximum = Some items =>
  all valid_word32 items /\ valid_u64 (size items) /\ size items <= maximum.
proof.
move=> valid success.
have [start [offset [header [limit entries]]]] :=
  decode_array_bytes32_entries data items base head maximum valid success.
have [range _] := read_usize_some_valid data start (size items) valid header.
split; last done.
rewrite -(all_nthP valid_word32 items []) => i bounds.
exact: (read_word_valid data (nth [] items i) (start + HASH_LEN + HASH_LEN * i)
  valid (entries i bounds)).
qed.

lemma decode_array_bytes32_encode_cat (prefix suffix : bytes) (items : bytes list)
    (base head maximum : int) :
  all valid_word32 items => valid_u64 (size items) => size items <= maximum =>
  decode_offset (prefix ++ (encode_bytes32_array items ++ suffix)) base head = Some (size prefix) =>
  decode_array_bytes32 (prefix ++ (encode_bytes32_array items ++ suffix)) base head maximum = Some items.
proof.
move=> valid range limit offset.
have header := encode_bytes32_array_length prefix suffix items range.
rewrite (decode_array_bytes32_resolved _ base head maximum (size prefix) (size items) offset header).
rewrite iffalse 1:/# (all_some_mkseq_some _ (size items) items [] (size_ge0 items)) /=.
move=> i bounds.
have word_length : size (word_from_usize (size items)) = HASH_LEN
  by have := word_from_usize_valid (size items); rewrite /valid_word32 /valid_bytes; smt().
have consumed : size (prefix ++ word_from_usize (size items)) = size prefix + HASH_LEN
  by rewrite size_cat word_length.
rewrite /encode_bytes32_array -(catA (word_from_usize (size items)) (flatten items) suffix).
rewrite catA -consumed.
exact: (word_array_read_nth (prefix ++ word_from_usize (size items)) suffix items i valid bounds).
qed.

(* The encoder is an array tail. This full layout adds its relative head
   word, then permits arbitrary surrounding bytes, including trailing data. *)
lemma decode_array_bytes32_roundtrip (prefix suffix : bytes) (items : bytes list) (maximum : int) :
  all valid_word32 items => valid_u64 (size items) => size items <= maximum =>
  decode_array_bytes32
    (prefix ++ (word_from_usize HASH_LEN ++ (encode_bytes32_array items ++ suffix)))
    (size prefix) (size prefix) maximum = Some items.
proof.
move=> valid range limit.
have power64 : 2 ^ 64 = 18446744073709551616 by ring.
have offset_range : valid_u64 HASH_LEN by rewrite valid_u64_range /HASH_LEN power64.
have offset := decode_offset_cat prefix (encode_bytes32_array items ++ suffix)
    (size prefix) HASH_LEN offset_range.
have word_length : size (word_from_usize HASH_LEN) = HASH_LEN
  by have := word_from_usize_valid HASH_LEN; rewrite /valid_word32 /valid_bytes; smt().
rewrite catA.
apply (decode_array_bytes32_encode_cat (prefix ++ word_from_usize HASH_LEN) suffix items
  (size prefix) (size prefix) maximum valid range limit).
rewrite size_cat word_length.
by move: offset; rewrite catA.
qed.
