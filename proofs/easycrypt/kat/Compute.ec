(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Reduction rules for evaluation. The standard operators iota_, nseq, iter and
   integer exponentiation are specified by axioms, so `cbv` cannot evaluate
   them. Each rule below is a proven lemma that unfolds one of them by one
   step when its side condition evaluates to true. Only the known-answer test
   files import this theory. *)
require import AllCore List IntDiv.

lemma iota_c0 (i n : int) : n <= 0 => iota_ i n = [].
proof. exact: iota0. qed.

lemma iota_cS (i n : int) : 0 < n => iota_ i n = i :: iota_ (i + 1) (n - 1).
proof. by move=> gt0_n; rewrite -{1}(: n - 1 + 1 = n) 1:/# iotaS 1:/#. qed.

hint simplify iota_c0, iota_cS.

lemma nseq_c0 ['a] (n : int) (x : 'a) : n <= 0 => nseq n x = [].
proof. by move=> le0_n; rewrite nseq0_le. qed.

lemma nseq_cS ['a] (n : int) (x : 'a) : 0 < n => nseq n x = x :: nseq (n - 1) x.
proof. by move=> gt0_n; rewrite -{1}(: n - 1 + 1 = n) 1:/# nseqS 1:/#. qed.

hint simplify nseq_c0, nseq_cS.

lemma iter_c0 ['a] (n : int) (f : 'a -> 'a) (x : 'a) : n <= 0 => iter n f x = x.
proof. exact: iter0. qed.

lemma iter_cS ['a] (n : int) (f : 'a -> 'a) (x : 'a) :
  0 < n => iter n f x = iter (n - 1) f (f x).
proof. by move=> gt0_n; rewrite -{1}(: n - 1 + 1 = n) 1:/# iterSr 1:/#. qed.

hint simplify iter_c0, iter_cS.

lemma pow_c0 (x n : int) : n = 0 => x ^ n = 1.
proof. by move=> ->; rewrite expr0. qed.

lemma pow_cS (x n : int) : 0 < n => x ^ n = x * x ^ (n - 1).
proof. by move=> gt0_n; rewrite -{1}(: n - 1 + 1 = n) 1:/# exprS 1:/#. qed.

hint simplify pow_c0, pow_cS.
