(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Offset-table foundation for the existing dynamic-array encoder.
   Payloads are already encoded byte strings. Empty payloads may share
   adjacent offsets; complete element-codec/Rust correspondence is separate. *)
require import AllCore List ByteDomain.
require import Shrincs ByteEncoding IntegerEncoding WordReaders AbiBytes WordArrays.

lemma offsets_sum_cat (xs ys : int list) : sumz (xs ++ ys) = sumz xs + sumz ys.
proof. rewrite /sumz; elim: xs => [|x xs ih] /=; smt(). qed.

lemma offsets_sum_rcons (xs : int list) (x : int) : sumz (rcons xs x) = sumz xs + x.
proof. by rewrite -cats1 offsets_sum_cat /sumz /=. qed.

lemma offsets_prefix_bounds (sizes : int list) (i : int) :
  all (fun n => 0 <= n) sizes => 0 <= sumz (take i sizes) <= sumz sizes.
proof.
move=> nonnegative.
have prefix_valid : all (fun n => 0 <= n) (take i sizes)
  by move: nonnegative; rewrite !allP; smt(mem_take).
have suffix_valid : all (fun n => 0 <= n) (drop i sizes)
  by move: nonnegative; rewrite !allP; smt(mem_drop).
have prefix_bound := sumz_ge0 (take i sizes) prefix_valid.
have suffix_bound := sumz_ge0 (drop i sizes) suffix_valid.
have := offsets_sum_cat (take i sizes) (drop i sizes).
rewrite cat_take_drop; smt().
qed.

lemma offsets_prefix_step (sizes : int list) (i : int) :
  0 <= i < size sizes =>
  sumz (take (i + 1) sizes) = sumz (take i sizes) + nth 0 sizes i.
proof. by move=> bounds; rewrite (take_nth 0 i sizes bounds) offsets_sum_rcons. qed.

lemma offsets_fold_position (sizes : int list) (start : int) (history : int list) :
  (foldl (fun (st : int * int list) n => (st.`1 + n, rcons st.`2 st.`1))
    (start, history) sizes).`1 = start + sumz sizes.
proof.
elim: sizes start history => [|n sizes ih] start history.
+ by rewrite /sumz.
+ rewrite /= ih /sumz /=; ring.
qed.

lemma offsets_fold_history (sizes : int list) (start : int) (prefix history : int list) :
  (foldl (fun (st : int * int list) n => (st.`1 + n, rcons st.`2 st.`1))
    (start, prefix ++ history) sizes).`2 =
  prefix ++ (foldl (fun (st : int * int list) n => (st.`1 + n, rcons st.`2 st.`1))
    (start, history) sizes).`2.
proof.
elim: sizes start history => [|n sizes ih] start history => //=.
by rewrite rcons_cat ih.
qed.

lemma offsets_fold_spec (sizes : int list) (start : int) (history : int list) :
  foldl (fun (st : int * int list) n => (st.`1 + n, rcons st.`2 st.`1))
    (start, history) sizes = (start + sumz sizes, history ++ offsets start sizes).
proof.
have position := offsets_fold_position sizes start history.
have recorded := offsets_fold_history sizes start history [].
move: recorded; rewrite cats0 /offsets; smt().
qed.

lemma offsets_nil (start : int) : offsets start [] = [].
proof. by rewrite /offsets. qed.

lemma offsets_cons (start n : int) (sizes : int list) :
  offsets start (n :: sizes) = start :: offsets (start + n) sizes.
proof. by rewrite /offsets /= offsets_fold_spec. qed.

lemma offsets_cat (start : int) (xs ys : int list) :
  offsets start (xs ++ ys) = offsets start xs ++ offsets (start + sumz xs) ys.
proof. by rewrite /offsets foldl_cat !offsets_fold_spec. qed.

lemma offsets_size (start : int) (sizes : int list) : size (offsets start sizes) = size sizes.
proof.
elim: sizes start => [|n sizes ih] start.
+ by rewrite offsets_nil.
+ by rewrite offsets_cons /= ih.
qed.

lemma offsets_nth (start : int) (sizes : int list) (i : int) :
  0 <= i < size sizes => nth 0 (offsets start sizes) i = start + sumz (take i sizes).
proof.
move=> bounds.
have decomposition := cat_take_insert_drop 0 i sizes bounds.
have prefix_length : size (take i sizes) = i by apply size_takel; smt().
have encoded : offsets start sizes = offsets start (take i sizes) ++
    offsets (start + sumz (take i sizes)) (nth 0 sizes i :: drop (i + 1) sizes)
  by have := offsets_cat start (take i sizes) (nth 0 sizes i :: drop (i + 1) sizes);
     rewrite decomposition.
by rewrite encoded nth_cat offsets_size prefix_length ltzz subzz offsets_cons.
qed.

lemma offsets_adjacent (start : int) (sizes : int list) (i : int) :
  0 <= i => i + 1 < size sizes =>
  nth 0 (offsets start sizes) (i + 1) = nth 0 (offsets start sizes) i + nth 0 sizes i.
proof.
move=> nonnegative fits.
have bounds : 0 <= i < size sizes by smt().
have next_bounds : 0 <= i + 1 < size sizes by smt().
rewrite (offsets_nth start sizes i bounds) (offsets_nth start sizes (i + 1) next_bounds).
rewrite (offsets_prefix_step sizes i bounds); ring.
qed.

lemma offsets_zero_length (start : int) (sizes : int list) (i : int) :
  0 <= i => i + 1 < size sizes =>
  (nth 0 (offsets start sizes) (i + 1) = nth 0 (offsets start sizes) i <=> nth 0 sizes i = 0).
proof. move=> nonnegative fits; rewrite (offsets_adjacent start sizes i nonnegative fits); smt(). qed.

lemma offsets_range (start : int) (sizes : int list) (i : int) :
  all (fun n => 0 <= n) sizes => 0 <= i < size sizes =>
  start <= nth 0 (offsets start sizes) i <= start + sumz sizes.
proof.
move=> nonnegative bounds; rewrite (offsets_nth start sizes i bounds).
have := offsets_prefix_bounds sizes i nonnegative; smt().
qed.

lemma offsets_unsigned (start : int) (sizes : int list) :
  0 <= start => all (fun n => 0 <= n) sizes => start + sumz sizes < 2 ^ 64 =>
  all valid_u64 (offsets start sizes).
proof.
move=> start_nonnegative nonnegative fits.
rewrite -(all_nthP valid_u64 (offsets start sizes) 0) offsets_size => i bounds.
have := offsets_range start sizes i nonnegative bounds.
rewrite valid_u64_range; smt().
qed.

lemma offsets_monotone (start : int) (sizes : int list) (i j : int) :
  all (fun n => 0 <= n) sizes => 0 <= i <= j => j < size sizes =>
  nth 0 (offsets start sizes) i <= nth 0 (offsets start sizes) j.
proof.
move=> nonnegative ordered fits.
have bounds_i : 0 <= i < size sizes by smt().
have bounds_j : 0 <= j < size sizes by smt().
have prefix_valid : all (fun n => 0 <= n) (take j sizes)
  by move: nonnegative; rewrite !allP; smt(mem_take).
have smaller := offsets_prefix_bounds (take j sizes) i prefix_valid.
rewrite (offsets_nth start sizes i bounds_i) (offsets_nth start sizes j bounds_j).
move: smaller; rewrite take_take iftrue 1:/#; smt().
qed.

lemma offsets_final_end (start : int) (sizes : int list) :
  0 < size sizes =>
  nth 0 (offsets start sizes) (size sizes - 1) + nth 0 sizes (size sizes - 1) = start + sumz sizes.
proof.
move=> nonempty.
have bounds : 0 <= size sizes - 1 < size sizes by smt().
rewrite (offsets_nth start sizes (size sizes - 1) bounds).
have := offsets_prefix_step sizes (size sizes - 1) bounds.
rewrite (_ : size sizes - 1 + 1 = size sizes) 1:/# take_size; smt().
qed.

lemma dynamic_offsets_count (elements : bytes list) :
  size (offsets (size elements * HASH_LEN) (map size elements)) = size elements.
proof. by rewrite offsets_size size_map. qed.

lemma dynamic_offsets_nth (elements : bytes list) (i : int) :
  0 <= i < size elements =>
  nth 0 (offsets (size elements * HASH_LEN) (map size elements)) i =
    size elements * HASH_LEN + size (flatten (take i elements)).
proof.
move=> bounds.
have mapped_bounds : 0 <= i < size (map size elements) by rewrite size_map.
by rewrite (offsets_nth (size elements * HASH_LEN) (map size elements) i mapped_bounds)
  -map_take -size_flatten.
qed.

lemma dynamic_offsets_adjacent (elements : bytes list) (i : int) :
  0 <= i => i + 1 < size elements =>
  nth 0 (offsets (size elements * HASH_LEN) (map size elements)) (i + 1) =
    nth 0 (offsets (size elements * HASH_LEN) (map size elements)) i + size (nth [] elements i).
proof.
move=> nonnegative fits.
have mapped_fits : i + 1 < size (map size elements) by rewrite size_map.
rewrite (offsets_adjacent (size elements * HASH_LEN) (map size elements) i nonnegative mapped_fits).
rewrite (nth_map []) 1:/#; trivial.
qed.

lemma dynamic_offsets_unsigned (elements : bytes list) :
  size elements * HASH_LEN + size (flatten elements) < 2 ^ 64 =>
  all valid_u64 (offsets (size elements * HASH_LEN) (map size elements)).
proof.
move=> fits; apply offsets_unsigned.
+ rewrite /HASH_LEN; smt(size_ge0).
+ rewrite all_map allP; smt(size_ge0).
+ by rewrite -size_flatten.
qed.

lemma dynamic_offset_words_valid (elements : bytes list) :
  all valid_word32
    (map word_from_usize (offsets (size elements * HASH_LEN) (map size elements))).
proof. rewrite all_map allP; smt(word_from_usize_valid). qed.

lemma dynamic_offset_table_size (elements : bytes list) :
  size (flatten (map word_from_usize (offsets (size elements * HASH_LEN) (map size elements)))) =
    size elements * HASH_LEN.
proof.
rewrite (word_array_flatten_size _ (dynamic_offset_words_valid elements)) size_map dynamic_offsets_count.
ring.
qed.

lemma encode_dynamic_array_size (elements : bytes list) :
  size (encode_dynamic_array elements) = HASH_LEN + size elements * HASH_LEN + size (flatten elements).
proof.
have word_length : size (word_from_usize (size elements)) = HASH_LEN
  by have := word_from_usize_valid (size elements); rewrite /valid_word32 /valid_bytes; smt().
have table_length := dynamic_offset_table_size elements.
rewrite /encode_dynamic_array; smt(size_cat).
qed.

lemma encode_dynamic_array_valid (elements : bytes list) :
  all is_bytes elements =>
  valid_bytes (HASH_LEN + size elements * HASH_LEN + size (flatten elements)) (encode_dynamic_array elements).
proof.
move=> valid; rewrite /valid_bytes encode_dynamic_array_size /=.
have payload_valid := is_bytes_flatten elements valid.
have table_valid := word_array_flatten_valid _ (dynamic_offset_words_valid elements).
have word_valid : is_bytes (word_from_usize (size elements))
  by have := word_from_usize_valid (size elements); rewrite /valid_word32 /valid_bytes; smt().
rewrite /encode_dynamic_array; smt(is_bytes_cat).
qed.

lemma flatten_element_slice (elements : bytes list) (i : int) :
  0 <= i < size elements =>
  take (size (nth [] elements i))
    (drop (size (flatten (take i elements))) (flatten elements)) = nth [] elements i.
proof.
move=> bounds.
have decomposition := cat_take_insert_drop [] i elements bounds.
have payload_split : flatten elements = flatten (take i elements) ++
    (nth [] elements i ++ flatten (drop (i + 1) elements))
  by rewrite -{1}decomposition flatten_cat flatten_cons.
by rewrite payload_split drop_size_cat // take_size_cat.
qed.

lemma encode_dynamic_array_element_slice (elements : bytes list) (i : int) :
  0 <= i < size elements =>
  take (size (nth [] elements i))
    (drop (HASH_LEN + nth 0 (offsets (size elements * HASH_LEN) (map size elements)) i)
      (encode_dynamic_array elements)) = nth [] elements i.
proof.
move=> bounds.
have word_length : size (word_from_usize (size elements)) = HASH_LEN
  by have := word_from_usize_valid (size elements); rewrite /valid_word32 /valid_bytes; smt().
have table_length := dynamic_offset_table_size elements.
have head_length : size (word_from_usize (size elements) ++
    flatten (map word_from_usize (offsets (size elements * HASH_LEN) (map size elements)))) =
    HASH_LEN + size elements * HASH_LEN by smt(size_cat).
rewrite (dynamic_offsets_nth elements i bounds) /encode_dynamic_array drop_catr.
+ rewrite head_length; smt(size_ge0).
rewrite head_length (_ : HASH_LEN + (size elements * HASH_LEN + size (flatten (take i elements))) -
  (HASH_LEN + size elements * HASH_LEN) = size (flatten (take i elements))) 1:/#.
exact: (flatten_element_slice elements i bounds).
qed.

lemma offset_words_read (prefix suffix : bytes) (values : int list) (i : int) :
  0 <= i < size values => valid_u64 (nth 0 values i) =>
  read_usize (prefix ++ (flatten (map word_from_usize values) ++ suffix))
    (size prefix + HASH_LEN * i) = Some (nth 0 values i).
proof.
move=> bounds valid.
have words_valid : all valid_word32 (map word_from_usize values)
  by rewrite all_map allP; smt(word_from_usize_valid).
have mapped_bounds : 0 <= i < size (map word_from_usize values) by rewrite size_map.
apply read_usize_encoded_word => //.
by rewrite (word_array_read_nth prefix suffix (map word_from_usize values) i words_valid mapped_bounds)
  (nth_map 0) 1:bounds.
qed.

lemma encode_dynamic_array_offset (prefix suffix : bytes) (elements : bytes list) (i : int) :
  0 <= i < size elements =>
  valid_u64 (nth 0 (offsets (size elements * HASH_LEN) (map size elements)) i) =>
  read_usize (prefix ++ (encode_dynamic_array elements ++ suffix))
    (size prefix + HASH_LEN + HASH_LEN * i) =
      Some (nth 0 (offsets (size elements * HASH_LEN) (map size elements)) i).
proof.
move=> bounds valid.
have table_bounds : 0 <= i < size (offsets (size elements * HASH_LEN) (map size elements))
  by rewrite dynamic_offsets_count.
have word_length : size (word_from_usize (size elements)) = HASH_LEN
  by have := word_from_usize_valid (size elements); rewrite /valid_word32 /valid_bytes; smt().
have read := offset_words_read (prefix ++ word_from_usize (size elements))
  (flatten elements ++ suffix) (offsets (size elements * HASH_LEN) (map size elements)) i table_bounds valid.
have position : size (prefix ++ word_from_usize (size elements)) + HASH_LEN * i =
    size prefix + HASH_LEN + HASH_LEN * i by smt(size_cat).
move: read; rewrite position /encode_dynamic_array; smt(catA).
qed.

lemma dynamic_array_resolve_offset (prefix suffix : bytes) (elements : bytes list) (i : int) :
  0 <= i < size elements =>
  size elements * HASH_LEN + size (flatten elements) < 2 ^ 64 =>
  decode_offset (prefix ++ (encode_dynamic_array elements ++ suffix))
    (size prefix + HASH_LEN) (size prefix + HASH_LEN + HASH_LEN * i) =
      Some (size prefix + HASH_LEN +
        (size elements * HASH_LEN + size (flatten (take i elements)))).
proof.
move=> bounds fits.
have table_bounds : 0 <= i < size (offsets (size elements * HASH_LEN) (map size elements))
  by rewrite dynamic_offsets_count.
have valid : valid_u64 (nth 0 (offsets (size elements * HASH_LEN) (map size elements)) i)
  by have := dynamic_offsets_unsigned elements fits; rewrite allP; smt(mem_nth).
by rewrite /decode_offset (encode_dynamic_array_offset prefix suffix elements i bounds valid)
  /omap /= (dynamic_offsets_nth elements i bounds).
qed.

lemma encode_dynamic_array_count (prefix suffix : bytes) (elements : bytes list) :
  valid_u64 (size elements) =>
  read_usize (prefix ++ (encode_dynamic_array elements ++ suffix)) (size prefix) = Some (size elements).
proof.
move=> valid.
have read := read_usize_roundtrip prefix
  (flatten (map word_from_usize (offsets (size elements * HASH_LEN) (map size elements))) ++
    (flatten elements ++ suffix)) (size elements) valid.
move: read; rewrite /encode_dynamic_array; smt(catA).
qed.
