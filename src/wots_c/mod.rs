// Copyright (C) 2026 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared WOTS-C chain walk and digit-sum grind primitives, plus the WOTS-C
//! signature wire type and its ABI codec.
//!
//! Mirrors Solidity `WOTSPlusC.sol`'s generic chain-walk core: `wots_chain_walk`
//! is one parameterized chain walk that per-tree callers (the stateless
//! hypertree and stateful UXMSS) bind with their own domain tag and address
//! layout. Path-specific binders live with their callers, not here.
//!
//! `Signature::to_bytes`/`from_bytes` are byte-identical to the pre-refactor
//! `envelope::encode_wots_c_signature_body`/`decode_wots_c_signature` (that
//! module has since been deleted); the hypertree codec embeds a WOTS-C
//! signature via `Signature::decode`.

use alloc::vec::Vec;

use crate::primitives::abi::{
    collect_hash_words, encode_bytes, encode_dynamic_array, encode_tuple, word_from_u32, AbiReader,
    Field,
};
use crate::primitives::hash::hash_node;
use crate::primitives::profiles::NUM_WOTS_CHAINS;
use crate::primitives::HASH_LEN;

/// Maximum grind counter for WOTS-C target-sum searches (stateless + stateful).
/// Distinct from `profiles::FORS_C_MAX_GRIND_COUNTER` (FORS-only).
pub(crate) const WOTS_C_MAX_GRIND_COUNTER: u32 = 1 << 24;

/// Value and step range for one WOTS-C chain walk.
#[derive(Clone, Copy)]
pub(crate) struct ChainWalk {
    pub value: [u8; HASH_LEN],
    pub start: u32,
    pub steps: u32,
}

/// Advance one WOTS-C chain from a revealed value by `walk.steps` hashes.
///
/// `tag` is the domain-separation string (`b"wots-c-chain"` or
/// `b"uxmss-wots-chain"`). `address_word` builds the per-step address from
/// `(chain_index, step)`.
pub(crate) fn wots_chain_walk(
    tag: &[u8],
    pk_seed: &[u8; HASH_LEN],
    address_word: impl Fn(u32) -> [u8; HASH_LEN],
    walk: ChainWalk,
) -> [u8; HASH_LEN] {
    let mut out = walk.value;
    for step_offset in 0..walk.steps {
        let step = walk.start + step_offset;
        let addr = address_word(step);
        out = hash_node(&[tag, pk_seed.as_ref(), addr.as_ref(), out.as_ref()]);
    }
    out
}

/// Find the lowest counter in `0..limit` for which `try_counter` returns
/// `Some`, paired with its payload.
///
/// Sequential fallback (default / `parallel` feature off). Kept byte-identical
/// to the parallel version below: both return the *lowest* winning counter.
#[cfg(not(feature = "parallel"))]
pub(crate) fn lowest_winning_counter<T>(
    limit: u32,
    try_counter: impl Fn(u32) -> Option<T>,
) -> Option<(u32, T)> {
    for counter in 0..limit {
        if let Some(t) = try_counter(counter) {
            return Some((counter, t));
        }
    }
    None
}

/// Parallel grind: shards the counter range across the rayon global pool.
///
/// Uses `find_map_first`, which returns the winner with the *lowest* counter
/// (matching sequential search order) rather than whichever thread finishes
/// first — this keeps signature bytes identical to the sequential grind, at
/// the cost of some parallel speedup (later shards may compute past the
/// eventual winner before the result is known).
#[cfg(feature = "parallel")]
pub(crate) fn lowest_winning_counter<T: Send>(
    limit: u32,
    try_counter: impl Fn(u32) -> Option<T> + Sync,
) -> Option<(u32, T)> {
    use rayon::prelude::*;
    (0..limit)
        .into_par_iter()
        .find_map_first(|counter| try_counter(counter).map(|t| (counter, t)))
}

/// Generic digit-sum grind: try counters until digit sum equals `target_sum`.
///
/// `digits_from_counter` returns the base-w digits for a candidate counter.
/// On success, `build_chains` produces the revealed chain values for those digits.
#[cfg(not(feature = "parallel"))]
pub(crate) fn grind_digit_sum<D, B, C>(
    max_counter: u32,
    target_sum: u32,
    digits_from_counter: D,
    build_chains: B,
) -> Option<(u32, C)>
where
    D: Fn(u32) -> Option<(u32, Vec<u32>)>,
    B: Fn(&[u32]) -> C,
{
    lowest_winning_counter(max_counter, |counter| {
        let (digit_sum, digits) = digits_from_counter(counter)?;
        (digit_sum == target_sum).then(|| build_chains(&digits))
    })
}

/// Generic digit-sum grind: try counters until digit sum equals `target_sum`.
///
/// `digits_from_counter` returns the base-w digits for a candidate counter.
/// On success, `build_chains` produces the revealed chain values for those digits.
#[cfg(feature = "parallel")]
pub(crate) fn grind_digit_sum<D, B, C>(
    max_counter: u32,
    target_sum: u32,
    digits_from_counter: D,
    build_chains: B,
) -> Option<(u32, C)>
where
    D: Fn(u32) -> Option<(u32, Vec<u32>)> + Sync,
    B: Fn(&[u32]) -> C + Sync,
    C: Send,
{
    lowest_winning_counter(max_counter, |counter| {
        let (digit_sum, digits) = digits_from_counter(counter)?;
        (digit_sum == target_sum).then(|| build_chains(&digits))
    })
}

/// WOTS-C signature: randomizer, target-sum grind counter, and one revealed
/// chain value per WOTS-C digit.
///
/// Kept `pub` (rather than `pub(crate)`, unlike the chain-walk primitives
/// above) because it is part of the crate's public wire-type surface: the
/// `tests/` integration suite and the `solana` workspace member reconstruct it
/// from their DTOs, importing it at its canonical path `crate::wots_c::Signature`
/// (they alias it locally as `WotsCSignature`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Randomizer mixed into WOTS-C digest derivation.
    pub randomizer: [u8; HASH_LEN],
    /// Counter mixed into WOTS-C digest derivation.
    pub counter: u32,
    /// One chain value per WOTS-C digit.
    pub chains: Vec<[u8; HASH_LEN]>,
}

impl Signature {
    /// ABI-encode the WOTS-C signature body. Byte-identical to the historical
    /// `envelope::encode_wots_c_signature_body`.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_tuple(alloc::vec![
            Field::Dynamic(encode_bytes(&self.randomizer)),
            Field::Static(word_from_u32(self.counter)),
            Field::Dynamic(encode_dynamic_array(
                self.chains.iter().map(|node| encode_bytes(node)).collect(),
            )),
        ])
    }

    /// Decode a WOTS-C signature body already located at `base` within a
    /// shared `AbiReader`. No trailing-bytes check here: `base` commonly
    /// sits inside a larger encoded envelope, so exhaustion is the calling
    /// top-level decoder's responsibility (see `from_bytes` for the
    /// standalone entrypoint that does check).
    pub(crate) fn decode(reader: &AbiReader, base: usize) -> Option<Self> {
        Some(Self {
            randomizer: reader.decode_bytes32_field(base, base)?,
            counter: reader.read_u32(base.checked_add(32)?)?,
            chains: collect_hash_words(reader.decode_array_bytes(
                base,
                base.checked_add(64)?,
                NUM_WOTS_CHAINS as usize,
            )?)?,
        })
    }

    /// Decode a standalone byte blob produced by `to_bytes`: a fresh `AbiReader`
    /// at base 0, rejecting trailing bytes. Byte-identical to the pre-refactor
    /// `envelope::decode_wots_c_signature` (that module has since been deleted).
    ///
    /// The hypertree codec instead decodes a WOTS-C signature embedded at an
    /// offset inside a larger shared `AbiReader` (via `decode`, above), where a
    /// trailing-bytes check would spuriously reject the rest of the envelope.
    /// This standalone entrypoint is the `to_bytes` round-trip counterpart, part
    /// of the public codec surface for external callers that hold an isolated
    /// WOTS-C signature blob.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let reader = AbiReader::new(data);
        let decoded = Self::decode(&reader, 0)?;
        reader.finish()?;
        Some(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample_signature() -> Signature {
        Signature {
            randomizer: [0x5A; HASH_LEN],
            counter: 0x0BAD_F00D,
            chains: vec![[0x11; HASH_LEN], [0x22; HASH_LEN], [0x33; HASH_LEN]],
        }
    }

    #[test]
    fn to_bytes_from_bytes_round_trips() {
        let signature = sample_signature();
        let encoded = signature.to_bytes();
        let decoded = Signature::from_bytes(&encoded).expect("valid encoding must decode");
        assert_eq!(decoded, signature);
        assert_eq!(decoded.to_bytes(), encoded);
    }

    #[test]
    fn from_bytes_rejects_trailing_bytes() {
        let mut encoded = sample_signature().to_bytes();
        encoded.push(0x00);
        assert!(Signature::from_bytes(&encoded).is_none());
    }
}
