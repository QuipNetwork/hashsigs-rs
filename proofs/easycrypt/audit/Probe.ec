(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* Audit probe. It imports every theory of the development and prints the
   axioms in scope. audit/audit.sh compares the result with the allowlist. *)
require import Compute Search ByteDomain Shrincs Games GamesSanity CounterInvariant ByteEncoding.
require import IntegerEncoding WordReaders AbiBytes WordArrays DynamicOffsets.
print axiom.
